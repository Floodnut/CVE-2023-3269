# StackRot (CVE-2023-3269)

> 이 자료는 미완성입니다.

## 리눅스 커널 권한 상승 취약점

리눅스 커널 버전 6.1부터 6.4까지 "Stack Rot"이라고도 알려진 스택 확장 처리에서 발견된 취약점입니다.  
`Maple Tree`는 MM 쓰기 락을 올바르게 획득하지 않고 노드 교체를 수행할 수 있고 이로 인해 use-after-free 문제가 발생할 수 있습니다.  
권한 없는 로컬 사용자가 이 취약점을 이용하여 커널을 침해하고 권한을 상승시킬 수 있습니다.

StackRot은 메모리 관리 서브 시스템에서 발견되는 리눅스 커널 취약점이므로 거의 모든 커널 구성에 영향을 미치며 트리거하려면 최소한의 권한이 필요합니다.

RCU 콜백을 사용하여 메이플 노드가 해제됩니다.
하지만, 실제 메모리 할당 해제가 RCU grace-period 이후까지 지연된다는 점에 유의해야 합니다.

- RCU를 통해 데이터를 관리하는 경우, 데이터 구조의 변경이 발생하면 일정한 대기 기간(Grace-period)가 있습니다.
- 갱신되지 않은 데이터를 참조하는 스레드가 있는지 확인하기 위함이며 모든 쓰기 작업 쓰레드가 완료된 이후 대기 기간이 종료됩니다.

## 사전 지식

### Maple Tree

가상 메모리 영역을 관리하며 가상 메모리 영역을 나타내는 노드를 계층적 구조로 표현한 것 입니다.

- 리눅스 커널 6.1에 적용되었습니다.
- 페이지 단위로 메모리를 관리합니다.
- 각 노드는 가상 주소 범위와 그에 해당하는 물리 주소를 포함합니다.

프로세스가 동작하며 메모리 공간이 동적으로 할당/해제됩니다.

- 이때, 가상 메모리 영역의 할당과 해제를 담당합니다.
- 페이지 폴트(Page fault)가 발생한 상황에서 가상-물리 메모리간 매핑을 담당합니다.

```
Root Node
 └── Maple Node
      ├── Interval 1: [start_address1, end_address1]
      ├── Interval 2: [start_address2, end_address2]
      ├── ...
      ├── Interval 15: [start_address15, end_address15]
      └── Interval 16: [start_address16, end_address16]
```

### Maple Tree의 노드 교체 과정에서의 MM(Memory Management) 쓰기 락

가상 메모리 영역의 정보가 업데이트 되는 과정에서 노드 교체가 발생합니다.

- 프로세스의 메모리 맵핑이 변경되는 경우
- 가상 주소 공간이 확장 또는 축소되는 경우

이런 경우 업데이트 되는 정보가 안전하게 새로운 노드에 적용되기 위해 락을 사용합니다.

- 이를 통해서 쓰기에 대한 동시성 문제를 해결합니다.

### Use-After-Free 취약점

해제된 메모리 영역을 접근할 때 발생하는 문제이자 취약점 입니다.

- 메모리를 해제한 후 해당 메모리를 가리키던 댕글링 포인터에 접근하는 등의 동작으로 인해 유발될 수 있습니다.

### RCU (Read-Copy-Update)

`Copy-on-Write`와 같이 리눅스 커널에서 사용되는 동기화 메커니즘 입니다.

- 스레드가 공유하는 자원에 대해 읽기-쓰기가 동시에 발생할 때 이를 동기화 해줍니다.
- 읽기의 경우, 락을 걸지 않고 수행합니다.
- 쓰기의 경우, 데이터를 갱신하고 이전 버전 데이터를 정리합니다.
  - 이로 인해 쓰기 작업에서 일시적으로 오버헤드가 발생할 수 있습니다.
- 커널과 같이 읽기 작업의 빈도가 높고 쓰기 작업의 빈도가 늦거나 소요 시간이 짧은 경우 유리합니다.

## 취약점 분석

`mmap()` 시스템 콜은 메모리 맵핑을 위해 사용되는데, 이때마다 커널은 `vm_area_struct` 라는 구조체를 생성합니다. 이 구조체는 가상 메모리 영역을 나타냅니다.

이 구조체는 `include/linux/mm_types.h`에 존재하고 플래그, 내부 속성이나 맵핑 관련 세부 정보를 저장합니다.

```c
struct vm_area_struct {
  long unsigned int          vm_start;             /*     0     8 */
  long unsigned int          vm_end;               /*     8     8 */
  struct mm_struct *         vm_mm;                /*    16     8 */
  pgprot_t                   vm_page_prot;         /*    24     8 */
  long unsigned int          vm_flags;             /*    32     8 */
  union {
    struct {
      struct rb_node rb __attribute__((__aligned__(8))); /*    40    24 */
      /* --- cacheline 1 boundary (64 bytes) --- */
      long unsigned int rb_subtree_last; /*    64     8 */
    } __attribute__((__aligned__(8))) shared __attribute__((__aligned__(8))); /*    40    32 */
    struct anon_vma_name * anon_name;              /*    40     8 */
  } __attribute__((__aligned__(8)));               /*    40    32 */
  /* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
  struct list_head           anon_vma_chain;       /*    72    16 */
  struct anon_vma *          anon_vma;             /*    88     8 */
  const struct vm_operations_struct  * vm_ops;     /*    96     8 */
  long unsigned int          vm_pgoff;             /*   104     8 */
  struct file *              vm_file;              /*   112     8 */
  void *                     vm_private_data;      /*   120     8 */
  /* --- cacheline 2 boundary (128 bytes) --- */
  atomic_long_t              swap_readahead_info;  /*   128     8 */
  struct vm_userfaultfd_ctx  vm_userfaultfd_ctx;   /*   136     0 */

  /* size: 136, cachelines: 3, members: 14 */
  /* forced alignments: 1 */
  /* last cacheline: 8 bytes */
} __attribute__((__aligned__(8)));
```

2023년 7월 23일 기준 실제 구조체는 아래와 같습니다.

```c
/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	union {
		struct {
			/* VMA covers [vm_start; vm_end) addresses within mm */
			unsigned long vm_start;
			unsigned long vm_end;
		};
#ifdef CONFIG_PER_VMA_LOCK
		struct rcu_head vm_rcu; /* Used for deferred freeing. */
#endif
	};

	struct mm_struct *vm_mm; /* The address space we belong to. */
	pgprot_t vm_page_prot; /* Access permissions of this VMA. */

	/*
	 * Flags, see mm.h.
	 * To modify use vm_flags_{init|reset|set|clear|mod} functions.
	 */
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __private __vm_flags;
	};

#ifdef CONFIG_PER_VMA_LOCK
	int vm_lock_seq;
	struct vma_lock *vm_lock;

	/* Flag to indicate areas detached from the mm->mm_mt tree */
	bool detached;
#endif

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 *
	 */
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_lock &
					  * page_table_lock */
	struct anon_vma *anon_vma; /* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff; /* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct file *vm_file; /* File we map to (can be NULL). */
	void *vm_private_data; /* was vm_pte (shared mem) */

#ifdef CONFIG_ANON_VMA_NAME
	/*
	 * For private and shared anonymous mappings, a pointer to a null
	 * terminated string containing the name given to the vma, or NULL if
	 * unnamed. Serialized by mmap_lock. Use anon_vma_name to access.
	 */
	struct anon_vma_name *anon_name;
#endif
#ifdef CONFIG_SWAP
	atomic_long_t swap_readahead_info;
#endif
#ifndef CONFIG_MMU
	struct vm_region *vm_region; /* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy; /* NUMA policy for the VMA */
#endif
#ifdef CONFIG_NUMA_BALANCING
	struct vma_numab_state *numab_state; /* NUMA Balancing state */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
} __randomize_layout;
```

이후, 커널이 페이지 폴트나 기타 메모리 관련 시스템 콜을 확인하면, 메모리 주소 만을 이용해 VMA를 빠르게 조회해야 합니다.

이전에는 가상 메모리 영역(VMAs)는 레드-블랙 트리를 사용하여 관리되었지만 리눅스 커널 6.1부터 메이플 트리로 관리 구조가 마이그레이션 되었습니다.  
메이플 트리는 `RCU(Read-Copy-Update)-Safe`한 B-트리 자료구조로, 중복되지 않는 범위를 저장하는 데 최적화되어 있습니다.

> `RCU-Safe` 하다는 것은 `RCU`를 통해서 변경되는 자료구조가 멀티 스레딩 등의 환경에 대해 데이터 일관성을 보장한다는 것을 의미합니다.

이런 메이플 트리의 복잡한 특징은 코드 구조에 복잡성을 증가시켰고 StackRot 취약점을 유발합니다.

메이플 트리는 메이플 노드들로 구성됩니다. 다음을 가정해봅시다.

- 메이플 트리가 단일 루트 노드만을 가지고 있습니다.
- 각 노드는 최대 16개의 연속된 메모리 주소 공간을 가질 수 있습니다.
- 각 주소 공간은 빈 주소 공간이나 VMA를 가리킬 수 있습니다.
- 두 주소 공간 사이에는 또 다른 공간이 없습니다.

```c
struct maple_range_64 {
	struct maple_pnode *       parent;               /*     0     8 */
	long unsigned int          pivot[15];            /*     8   120 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	union {
		void *       slot[16];             /*   128   128 */
		struct {
			void *     pad[15];              /*   128   120 */
			/* --- cacheline 3 boundary (192 bytes) was 56 bytes ago --- */
			struct maple_metadata meta;      /*   248     2 */
		};                                 /*   128   128 */
	};                                   /*   128   128 */

	/* size: 256, cachelines: 4, members: 3 */
};
```

`maple_range_64` 구조체를 살펴보면 다음과 같이 메이플 노드를 표현합니다.

- `Pivot`은 16개의 공간(interval)의 끝점을 나타냅니다.
- `Slot`은 노드가 리프 노드로 간주될 때 VMA 구조체를 참조하는 데 사용됩니다.
- `Pivot`과 `Slot`의 레이아웃은 아래와 같이 표현해볼 수 있습니다.

```
 Slots -> | 0 | 1 | 2 | ... | 12 | 13 | 14 | 15 |
          ┬   ┬   ┬   ┬     ┬    ┬    ┬    ┬    ┬
          │   │   │   │     │    │    │    │    └─ Implied maximum
          │   │   │   │     │    │    │    └─ Pivot 14
          │   │   │   │     │    │    └─ Pivot 13
          │   │   │   │     │    └─ Pivot 12
          │   │   │   │     └─ Pivot 11
          │   │   │   └─ Pivot 2
          │   │   └─ Pivot 1
          │   └─ Pivot 0
          └─  Implied minimum
```

동시 수정(쓰기)이 이루어지면, 메이플 트리는 `Writer`에게 `배타 락(Exclusive Lock)`을 보장합니다.  
VMA 트리의 경우, `배타 락`은 `MM 쓰기 락`에 해당합니다.

메이플 트리를 읽는 데는 두 가지 옵션이 있습니다.

- 첫 번째 옵션은 `MM 읽기 락`을 유지하는 것으로, 이로 인해 `Writer`가 `MM 읽기-쓰기 락`에 의해 차단됩니다.
- 두 번째 옵션은 `RCU 임계 영역(Critical Section)`에 진입하는 것입니다.

이로 인해 `Writer`는 락에 차단되지 않고, 메이플 트리가 `RCU-Safe`하기 때문에 읽는 동안 `Reader`는 작업을 계속할 수 있습니다.

- 대부분의 기존 VMA 액세스는 첫 번째 옵션을 선택합니다.
- 하지만, `lockless 페이지 폴트` 같이 퍼포먼스가 중요한 몇몇 경우에는 두 번째 옵션이 채택됩니다.

그러나 특별히 주의해야 할 추가적인 측면이 있습니다. 이는 스택 확장과 관련된 것으로, 스택은 `MAP_GROWSDOWN` 플래그로 매핑된 메모리 영역을 나타내며, 해당 영역 아래의 주소에 접근할 때 자동으로 확장됩니다.

> `MAP_GROWSDOWN` 는 리눅스 `mmap()` 시스템 콜을 통해 메모리 매핑을 할 때 사용하는 옵션입니다.  
> 스택 영역을 매핑할 때 해당 영역의 주소가 감소하면서 스택을 자동으로 확장할 수 있게 됩니다.

이러한 경우, 해당 VMA의 시작 주소와 메이플 트리 내의 연관된 공간이 조정됩니다. 특히 이러한 조정은 `MM 쓰기 락`을 획득하지 않고 수행됩니다.

```c
static inline
void do_user_addr_fault(struct pt_regs *regs,
                        unsigned long error_code,
                        unsigned long address)
{
	// ...

	if (unlikely(!mmap_read_trylock(mm))) {
		// ...
	}
	// ...
	if (unlikely(expand_stack(vma, address))) {
		// ...
	}

	// ...
}
```

일반적으로 스택 VMA와 이웃하는 VMA 사이에는 커널이 스택 보호를 시행하여 간격이 존재합니다. 이 상황에서 스택을 확장할 때는 메이플 노드의 Pivot 값만 업데이트하면 되는데, 이는 Atomic하게 수행될 수 있습니다.

```c
#include <linux/rcupdate.h>
#include <linux/slab.h>

struct my_data {
    int value;
    struct rcu_head rcu; // RCU 콜백을 위한 구조체
};

void my_rcu_callback(struct rcu_head *rcu) {
    struct my_data *data = container_of(rcu, struct my_data, rcu);
    kfree(data); // 메모리 해제
}

void some_function(void) {
    // 데이터를 동적으로 할당합니다.
    struct my_data *data = kmalloc(sizeof(struct my_data), GFP_KERNEL);
    if (!data) {
        // 할당 실패 처리
        return;
    }

    // 데이터에 값을 설정합니다.
    data->value = 11;

    // RCU 메커니즘에 의해 지연된 메모리 해제를 위해 RCU 콜백을 등록합니다.
    call_rcu(&data->rcu, my_rcu_callback);

    // 이후 데이터는 RCU 콜백이 호출된 후에 안전하게 접근할 수 있습니다.
}
```

그러나 이웃하는 VMA도 `MAP_GROWSDOWN` 플래그를 가지고 있다면 스택 보호가 시행되지 않습니다.  
결과적으로 스택 확장은 간격을 없앨 수 있습니다. 이런 상황에서는 메이플 노드 내의 간격 인터벌을 제거해야 합니다.  
메이플 트리가 `RCU-safe`하기 때문에 노드를 그 자리에서 덮어쓰는 것은 불가능합니다.
대신 새 노드가 생성되어 노드 교체를 유발하고, 이전 노드는 RCU 콜백을 사용하여 삭제됩니다.

```c
int expand_downwards(struct vm_area_struct *vma, unsigned long address)
{
	// ...

	if (prev) {
		if (!(prev->vm_flags & VM_GROWSDOWN) &&
		    vma_is_accessible(prev) &&
		    (address - prev->vm_end < stack_guard_gap))
			return -ENOMEM;
	}

	// ...
}
```

RCU 콜백은 기존의 모든 RCU 임계 영역이 해제된 후에만 호출됩니다. 그러나 VMA에 접근할 때 문제가 발생하는데, MM 읽기 락만 보유하고 RCU 임계 영역에 진입하지 않기 때문입니다. 따라서 이론적으로는 콜백이 언제든지 호출될 수 있으며, 이로 인해 이전 메이플 노드의 해제가 발생할 수 있습니다. 그러나 이전 노드에 대한 포인터가 이미 가져와진 경우가 있을 수 있으며, 이후에 해당 노드에 접근하려고 할 때 use-after-free가 발생할 수 있습니다.

UAF가 발생하는 과정을 역으로 살펴보면 다음과 같습니다.

```c
  - CPU 0 -                                        - CPU 1 -

  mm_read_lock()                                    mm_read_lock()
  expand_stack()                                    find_vma_prev()
    expand_downwards()                                mas_walk()
      mas_store_prealloc()                              mas_state_walk()
        mas_wr_story_entry()                              mas_start()
          mas_wr_modify()                                   mas_root()
            mas_wr_node_store()                               node = rcu_dereference_check()
              mas_replace()                                   [ 노드 포인터가 기록됩니다. ]
                mas_free()
                  ma_free_rcu()
                    call_rcu(&mt_free_rcu)
                    [ The node is dead ]
  mm_read_unlock()

  [ 다음 RCU grace period를 기다립니다. ]
  rcu_do_batch()                                      mas_prev()
    mt_free_rcu()                                       mas_prev_entry()
      kmem_cache_free()                                   mas_prev_nentry()
      [ The node is freed ]                                 mas_slot()
                                                              mt_slot()
                                                                rcu_dereference_check(node->..)
                                                                [ UAF가 이 지점에서 발생합니다. ]
                                                    mm_read_unlock()
```

## 어떻게 수정되었나요?

## 참고 자료

- https://github.com/lrh2000/StackRot
- https://www.openwall.com/lists/oss-security/2023/07/05/1
- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9471f1f2f50282b9e8f59198ec6bb738b4ccc009
- https://github.com/torvalds/linux
  - https://github.com/Floodnut/linux/blob/master/mm/mmap.c
- https://stackoverflow.com/questions/56893353/analyzing-memory-mapping-of-a-process-with-pmap-stack/56920770#56920770
- https://bugzilla.kernel.org/show_bug.cgi?id=203913
- https://stackoverflow.com/questions/56888725/why-is-map-growsdown-mapping-does-not-grow
- https://www.kernel.org/doc/Documentation/RCU/whatisRCU.txt
- https://lore.kernel.org/linux-mm/20220228143633.r4zoemgtmrq4uzvb@revolver/
