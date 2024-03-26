#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/kernel.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>

// extern struct bpf_struct_ops bpf_page_cache_ext_ops;
static const struct btf_type *page_cache_ext_eviction_ctx_type;
struct page_cache_ext_ops *page_cache_ext_ops = NULL;

static int bpf_page_cache_ext_init(struct btf *btf)
{
	u32 type_id;

	type_id = btf_find_by_name_kind(btf, "page_cache_ext_eviction_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0) {
		pr_err("page_cache_ext: failed to find struct page_cache_ext_eviction_ctx\n");
		return -EINVAL;
	}
	page_cache_ext_eviction_ctx_type = btf_type_by_id(btf, type_id);
	return 0;
}

// What helpers are available?
static const struct bpf_func_proto *
bpf_page_cache_ext_get_func_proto(enum bpf_func_id func_id,
				  const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id);
	}
}

// Only pass pointers as arguments. Taken from sched_ext.
static bool bpf_page_cache_ext_is_valid_access(int off, int size,
					       enum bpf_access_type type,
					       const struct bpf_prog *prog,
					       struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_page_cache_ext_btf_struct_access(struct bpf_verifier_log *log,
						const struct bpf_reg_state *reg,
						int off, int size)
{
	// For each of the allowed types, allow read access.
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == page_cache_ext_eviction_ctx_type) {
		if (off + size > sizeof(struct page_cache_ext_eviction_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	}

	return -EACCES;
}

static int bpf_page_cache_ext_reg(void *kdata)
{
	pr_info("page_cache_ext: Registering struct ops\n");
	WRITE_ONCE(page_cache_ext_ops, kdata);
	return 0;
}

static void bpf_page_cache_ext_unreg(void *kdata)
{
	// Opposite of bpf_page_cache_ext_reg.
	// Not needed yet.
	pr_info("page_cache_ext: Unregistering struct ops\n");
	WRITE_ONCE(page_cache_ext_ops, NULL);
}

static int bpf_page_cache_ext_init_member(const struct btf_type *t,
					  const struct btf_member *member,
					  void *kdata, const void *udata)
{
	// Initialize attributes of struct_ops. Not for the function pointers.
	// For example, sched_ext uses it to initialize timeout, flags, etc.
	// Not needed yet.
	return 0;
}

static int bpf_page_cache_ext_check_member(const struct btf_type *t,
					   const struct btf_member *member,
					   const struct bpf_prog *prog)
{
	// Check the attached member functions or attributes.
	// Not needed yet.
	return 0;
}

static int bpf_page_cache_ext_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_page_cache_ext_verifier_ops = {
	.get_func_proto = bpf_page_cache_ext_get_func_proto,
	.is_valid_access = bpf_page_cache_ext_is_valid_access,
	.btf_struct_access = bpf_page_cache_ext_btf_struct_access,
};

// Callbacks to define the struct_ops map
struct bpf_struct_ops bpf_page_cache_ext_ops = {
	.verifier_ops = &bpf_page_cache_ext_verifier_ops,
	.init = bpf_page_cache_ext_init,
	.reg = bpf_page_cache_ext_reg,
	.unreg = bpf_page_cache_ext_unreg,
	.init_member = bpf_page_cache_ext_init_member,
	.check_member = bpf_page_cache_ext_check_member,
	.validate = bpf_page_cache_ext_validate,
	.name = "page_cache_ext_ops",
};