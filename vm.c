#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// os hw3
void pagefault(void)
{
    uint va = rcr2(); 
    struct proc *p = myproc();

    uint max_stack_bottom_va = p->user_stack_bottom;

    if (PGROUNDDOWN(va) < KERNBASE &&
        PGROUNDDOWN(va) >= max_stack_bottom_va &&
        p->stack_pages_allocated < p->max_stack_pages)
    {
        pte_t *pte = walkpgdir(p->pgdir, (char*)PGROUNDDOWN(va), 0);
        if (pte && (*pte & PTE_P)) {
            cprintf("[Pagefault] Invalid access! (already present page: va=0x%x pid=%d)\n", va, p->pid);
            p->killed = 1;
            return;
        }
        char *mem = kalloc();
        if (mem == 0) {
            cprintf("[Pagefault] Invalid access! (kalloc failed during stack growth: pid=%d, va=0x%x)\n", p->pid, va);
            p->killed = 1;
            return;
        }
        memset(mem, 0, PGSIZE); 
        if (mappages(p->pgdir, (char*)PGROUNDDOWN(va), PGSIZE, V2P(mem), PTE_W|PTE_U|PTE_P) < 0) {
            cprintf("[Pagefault] Invalid access! (mappages failed during stack growth: pid=%d, va=0x%x)\n", p->pid, va);
            kfree(mem);
            p->killed = 1;
            return;
        }

        p->stack_pages_allocated++; 
        cprintf("[Pagefault] Allocate new page! (pid=%d, current pages=%d, fault_va=0x%x)\n", p->pid, p->stack_pages_allocated, PGROUNDDOWN(va));
        lcr3(V2P(p->pgdir));
        return; 
    }

    cprintf("[Pagefault] Invalid access! (Stack Overflow or access outside stack region: va=0x%x pid=%d)\n", va, p->pid);
    p->killed = 1;
}

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

  if(newsz >= kernbase)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = pgroundup(oldsz);
  for(; a < newsz; a += pgsize){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, pgsize);
    if(mappages(pgdir, (char*)a, pgsize, v2p(mem), pte_w|pte_u) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

// os hw3
int
mappages_no_present(pde_t *pgdir, char *va, uint size, uint perm)
{
  pte_t *pte;
  uint a;

  for (a = PGROUNDDOWN((uint)va); a < (uint)va + size; a += PGSIZE) {
    pte = walkpgdir(pgdir, (char*)a, 1); 
    if (!pte)
      return -1;
    *pte = (0 | perm);
  }
  return 0;
}

int
allocuvm_stack(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint va;
  uint stack_top_va = PGROUNDDOWN(KERNBASE - PGSIZE); 
  uint stack_bottom_limit_va = PGROUNDDOWN(KERNBASE - newsz); 

  if (newsz >= KERNBASE)
    return 0; 

  mem = kalloc();
  if (mem == 0) {
    cprintf("allocuvm_stack: kalloc failed for initial stack page\n");
    return 0;
  }
  memset(mem, 0, PGSIZE);

  if (mappages(pgdir, (char*)stack_top_va, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0) {
    cprintf("allocuvm_stack: mappages failed for initial stack page\n");
    kfree(mem);
    return 0;
  }

  for (va = stack_top_va - PGSIZE; va >= stack_bottom_limit_va; va -= PGSIZE) {
    if (mappages_no_present(pgdir, (char*)va, PGSIZE, PTE_W|PTE_U) < 0) {
        cprintf("allocuvm_stack: failed to create non-present PTE for stack growth\n");
        return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// vm.c

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;
  struct proc *curproc = myproc(); // 현재 부모 프로세스

  if((d = setupkvm()) == 0)
    return 0;

  // 스택의 가장 낮은 가상 주소 한계 계산
  // curproc->max_stack_pages는 fork 시점에 부모의 값을 그대로 복사받을 것이므로 유효합니다.
  uint stack_bottom_limit_va = KERNBASE - (curproc->max_stack_pages * PGSIZE);

  // 0부터 sz(코드/데이터/힙의 끝)까지 순회
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist"); // 이 부분은 pte가 존재하지 않으면 여전히 panic

    // PTE_P (Present) 비트가 설정되어 있지 않은 경우
    if(!(*pte & PTE_P)) {
      // 해당 가상 주소 i가 스택 범위 내에 있는지 확인합니다.
      // 스택은 KERNBASE에서 아래로 자라므로, i >= stack_bottom_limit_va 이고 i < KERNBASE 여야 합니다.
      if (i >= stack_bottom_limit_va && i < KERNBASE) {
        // 이 페이지는 스택 영역에 속하며, 아직 물리 페이지가 할당되지 않은 상태입니다.
        // 자식 프로세스에도 동일하게 PTE_P가 0인 페이지 엔트리를 생성합니다.
        // mappages_no_present와 유사한 로직이 필요합니다.
        // walkpgdir를 호출하여 PTE를 생성하고, PTE_P를 제외한 권한 비트를 설정합니다.
        pte_t *child_pte = walkpgdir(d, (void*)i, 1); // 자식의 pgdir에 PTE 생성 (없으면 생성)
        if (!child_pte) {
          // PTE 생성 실패 시, 생성된 자식 pgdir을 해제하고 0을 반환합니다.
          freevm(d);
          return 0;
        }
        // 부모의 PTE에서 PTE_P 비트만 제외하고 나머지 플래그를 자식 PTE에 복사합니다.
        // PTE_ADDR(*pte)는 어차피 0일 것이므로 중요하지 않습니다.
        *child_pte = ((*pte) & ~PTE_P); // PTE_P를 뺀 나머지 플래그만 복사

        // 이 페이지는 물리적 할당이 없으므로 mem = kalloc() 및 copyuvm_body(mem, i)를 건너뜝니다.
        continue; // 다음 페이지로 넘어갑니다.
      } else {
        // 스택 범위 밖이지만 PTE_P가 0인 경우 (예: 힙의 빈 공간, 또는 다른 비정상적인 상황)
        // 기존 allocuvm은 힙 확장에서 PTE_P 없는 페이지를 만들지 않으므로,
        // 이 경우는 비정상적인 상황일 가능성이 높습니다.
        // 하지만 과제는 스택에 대해서만 언급했으므로, 다른 영역의 PTE_P=0은 기존처럼 panic을 유지할 수 있습니다.
        // 요구사항이 '스택'에 대해서만 panic을 발생시키지 말라고 했으므로,
        // 스택이 아닌 영역에서 PTE_P가 없으면 기존처럼 panic을 유지하는 것이 합리적입니다.
        // 따라서, 현재 코드는 이 else 블록에 진입하면 panic("copyuvm: pte should exist")에 걸릴 수 있습니다.
        // 이를 방지하려면 `panic("copyuvm: pte should exist");`를 아래로 옮겨야 합니다.
      }
    }

    // PTE_P가 1인 경우 (정상적으로 매핑된 페이지)
    // 기존 copyuvm 로직 수행
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0)
      goto bad;
  }
  // KERNBASE 부터 스택의 가장 낮은 한계까지의 스택 공간에 대해
  // PTE_P가 0인 페이지 엔트리를 자식에게도 생성해야 합니다.
  // 위 for 루프는 `sz`까지만 돌기 때문에 스택 영역 전체를 포괄하지 못할 수 있습니다.
  // 스택 영역은 KERNBASE에서 아래로 sz와 독립적으로 존재하기 때문입니다.
  // 그러므로 스택 영역에 대한 별도의 순회가 필요합니다.
  
  // 스택 영역은 i < KERNBASE 이면서 i >= stack_bottom_limit_va 입니다.
  // 위 for 루프는 i < sz 까지만 돕니다. 만약 sz가 stack_bottom_limit_va보다 작다면
  // 스택 영역의 PTE_P=0인 부분은 복사되지 않을 수 있습니다.
  // 예를 들어, sz=10000000이고 스택이 KERNBASE-4*PGSIZE=0xFBE00000 부터 시작하면 for문이 스택 영역에 도달하지 못합니다.
  // 따라서, 스택 영역 복사는 별도의 루프에서 처리하는 것이 안전합니다.
  
  // -- 스택의 PTE_P=0인 가상 페이지 복사 --
  // 이 부분은 위에 PTE_P가 0인 경우의 `if` 블록에서 처리되므로,
  // `for(i=0; i<sz; ...)` 루프만으로 스택 영역도 커버한다면 괜찮습니다.
  // 그러나 일반적인 xv6 `sz`는 힙의 상단이고, 스택은 KERNBASE에서 내려오므로,
  // `i < sz` 조건으로 스택 영역을 모두 커버하기 어렵습니다.
  // 따라서, 스택 영역 복사를 위한 별도의 루프를 추가해야 합니다.
  
  // 올바른 `copyuvm`은 `0`부터 `KERNBASE`까지 순회해야 합니다.
  // 또는, 코드/데이터/힙 영역과 스택 영역을 별도로 순회해야 합니다.
  // 현재 `for(i=0; i < sz; i += PGSIZE)` 루프는 오직 `sz`까지의 영역만 커버합니다.
  // 즉, `KERNBASE`에서 `sz`까지의 영역(스택 영역)을 복사하지 않습니다.
  // 이 루프는 스택 영역을 전혀 건드리지 않습니다.
  // 기존 `exec`에서 `sz`를 스택이 시작하는 지점 바로 위로 올렸다면 `sz`가 스택 영역에 포함되지만,
  // 우리의 `exec` 수정본에서는 `sz`는 코드/데이터/힙의 끝을 의미하고 스택은 KERNBASE에서 시작합니다.
  // 따라서, `sz`와 `KERNBASE` 사이에 존재하는 스택 영역에 대한 명시적인 처리가 필요합니다.
  
  // XV6의 일반적인 copyuvm은 `sz` (user limit)까지 복사하고
  // 스택은 별도의 `allocuvm`으로 할당된 곳이므로, 
  // 스택 영역은 `sz`와는 별개로 존재하는 가상 주소 공간입니다.
  // 따라서, `copyuvm`의 `sz` 인자를 스택의 시작 지점인 `KERNBASE`까지 확장하고,
  // `i < KERNBASE`까지 루프를 돌도록 변경하는 것이 더 합리적입니다.
  
  // --- 변경된 copyuvm 루프 ---
  // `sz` 대신 `KERNBASE`까지 순회하도록 변경
  // (sz는 이제 코드/데이터/힙의 크기만 나타냄)
  for(i = 0; i < KERNBASE; i += PGSIZE){ // KERNBASE까지 모든 사용자 가상 주소 공간 순회
    // 이 시점에서 pte가 존재하지 않는다는 것은 panic.
    // 하지만, 스택 영역의 PTE_P=0인 경우는 허용.
    // 따라서, pte가 존재하지 않으면 panic이 맞는 동작입니다.
    // 즉, walkpgdir(pgdir, (void*)i, 0) == 0 인 경우
    //   -> 이 부분은 스택 영역 내에서 PTE_P=0 인 경우에도 PTE 자체는 존재해야 합니다.
    //      만약 PTE 자체가 없다면, 그건 스택 확장을 위해 PTE를 만들지 않은 경우입니다.
    //      이 경우, 해당 주소에 접근 시 페이지 폴트가 나므로 괜찮습니다.
    //      하지만 과제 요구사항은 "page entry는 생성하되 physical page는 할당하지 않음" 이므로,
    //      PTE는 존재해야 합니다.
    //      즉, `walkpgdir(pgdir, (void*)i, 0)`은 항상 `0`이 아니어야 합니다.
    //      만약 `allocuvm_stack`에서 `mappages_no_present`와 같은 함수를 사용하여 PTE를 생성했다면,
    //      이 `panic`은 발생하지 않을 것입니다.
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0) {
      // PTE가 없는 경우, 해당 주소가 스택 범위 내에 있고 KERNBASE보다 작으면 스택 확장 대상.
      // 그렇지 않으면 진짜 비정상적인 상황.
      if (i >= stack_bottom_limit_va && i < KERNBASE) {
         // 스택 영역의 PTE 없는 가상 주소. 자식에게도 PTE 없이 그대로 둡니다.
         // 이 경우는 페이지 폴트 핸들러가 처리합니다.
         // copyuvm은 이 경우 아무것도 하지 않고 넘어갑니다.
         continue;
      }
      panic("copyuvm: pte should exist for non-stack or mapped stack regions");
    }

    // PTE_P (Present) 비트가 설정되어 있지 않은 경우
    if(!(*pte & PTE_P)) {
      // 해당 가상 주소 i가 스택 범위 내에 있는지 확인합니다.
      if (i >= stack_bottom_limit_va && i < KERNBASE) {
        // 스택 영역에 속하며, 아직 물리 페이지가 할당되지 않은 PTE입니다.
        // 자식 프로세스에도 동일하게 PTE_P가 0인 페이지 엔트리를 생성합니다.
        pte_t *child_pte = walkpgdir(d, (void*)i, 1); // 자식의 pgdir에 PTE 생성 (없으면 생성)
        if (!child_pte) {
          freevm(d);
          return 0;
        }
        *child_pte = ((*pte) & ~PTE_P); // PTE_P를 뺀 나머지 플래그만 복사
        continue; // 다음 페이지로 넘어갑니다.
      } else {
        // 스택 범위 밖인데 PTE_P가 0인 경우 (비정상)
        // 기존 `copyuvm`은 이런 상황을 가정하지 않으므로 panic.
        // 과제는 스택에 대해서만 요구했으므로, 다른 영역은 여전히 panic
        panic("copyuvm: unpresent PTE for non-stack region");
      }
    }

    // PTE_P가 1인 경우 (정상적으로 매핑된 페이지)
    // 기존 copyuvm 로직 수행
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0)
      goto bad;
  }
  
  // 자식 프로세스의 sz는 부모의 sz와 동일하게 설정됩니다. (exec에서 sz는 코드/데이터/힙 영역만 포함)
  // 스택 관련 정보도 복사되어야 합니다.
  // 이는 fork 함수 내에서 p->stack_pages_allocated = curproc->stack_pages_allocated; 와 같이 이루어져야 합니다.
  
  return d;

bad:
  freevm(d);
  return 0;
}
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.

