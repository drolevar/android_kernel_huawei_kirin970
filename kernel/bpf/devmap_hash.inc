/* SPDX-License-Identifier: GPL-2.0 */
/* Control-plane algorithms from Toke Høiland-Jørgensen and subsequent fixes.
 * Included by devmap.c; see Documentation/bpf/devmap-hash-history/.
 */

static struct hlist_head *dev_map_create_hash(unsigned int entries)
{
	int i;
	struct hlist_head *hash;

	hash = kmalloc_array(entries, sizeof(*hash), GFP_KERNEL);
	if (hash != NULL)
		for (i = 0; i < entries; i++)
			INIT_HLIST_HEAD(&hash[i]);

	return hash;
}

static inline struct hlist_head *dev_map_index_hash(struct bpf_dtab *dtab,
						    int idx)
{
	return &dtab->dev_index_head[idx & (dtab->n_buckets - 1)];
}

struct bpf_dtab_netdev *__dev_map_hash_lookup_elem(struct bpf_map *map, u32 key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct hlist_head *head = dev_map_index_hash(dtab, key);
	struct bpf_dtab_netdev *dev;

	hlist_for_each_entry_rcu(dev, head, index_hlist)
		if (dev->idx == key)
			return dev;

	return NULL;
}

static int dev_map_hash_get_next_key(struct bpf_map *map, void *key,
				    void *next_key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	u32 idx, *next = next_key;
	struct bpf_dtab_netdev *dev, *next_dev;
	struct hlist_head *head;
	int i = 0;

	if (!key)
		goto find_first;

	idx = *(u32 *)key;

	dev = __dev_map_hash_lookup_elem(map, idx);
	if (!dev)
		goto find_first;

	next_dev = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(&dev->index_hlist)),
				    struct bpf_dtab_netdev, index_hlist);

	if (next_dev) {
		*next = next_dev->idx;
		return 0;
	}

	i = idx & (dtab->n_buckets - 1);
	i++;

 find_first:
	for (; i < dtab->n_buckets; i++) {
		head = dev_map_index_hash(dtab, i);

		next_dev = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),
					    struct bpf_dtab_netdev,
					    index_hlist);
		if (next_dev) {
			*next = next_dev->idx;
			return 0;
		}
	}

	return -ENOENT;
}

static void *dev_map_hash_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab_netdev *obj = __dev_map_hash_lookup_elem(map,
								*(u32 *)key);
	struct net_device *dev = obj ? obj->dev : NULL;

	return dev ? &dev->ifindex : NULL;
}

static int dev_map_hash_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *old_dev;
	int k = *(u32 *)key;
	unsigned long flags;
	int ret = -ENOENT;

	spin_lock_irqsave(&dtab->index_lock, flags);

	old_dev = __dev_map_hash_lookup_elem(map, k);
	if (old_dev) {
		dtab->items--;
		hlist_del_init_rcu(&old_dev->index_hlist);
		call_rcu(&old_dev->rcu, __dev_map_entry_free);
		ret = 0;
	}
	spin_unlock_irqrestore(&dtab->index_lock, flags);

	return ret;
}

static int __dev_map_hash_update_elem(struct net *net, struct bpf_map *map,
				     void *key, void *value, u64 map_flags)
{
	struct bpf_dtab *dtab = container_of(map, struct bpf_dtab, map);
	struct bpf_dtab_netdev *dev, *old_dev;
	u32 ifindex = *(u32 *)value;
	u32 idx = *(u32 *)key;
	unsigned long flags;

	if (unlikely(map_flags > BPF_EXIST || !ifindex))
		return -EINVAL;

	old_dev = __dev_map_hash_lookup_elem(map, idx);
	if (old_dev && (map_flags & BPF_NOEXIST))
		return -EEXIST;

	dev = __dev_map_alloc_node(net, dtab, ifindex, idx);
	if (IS_ERR(dev))
		return PTR_ERR(dev);

	spin_lock_irqsave(&dtab->index_lock, flags);

	if (old_dev) {
		hlist_del_rcu(&old_dev->index_hlist);
	} else {
		if (dtab->items >= dtab->map.max_entries) {
			spin_unlock_irqrestore(&dtab->index_lock, flags);
			call_rcu(&dev->rcu, __dev_map_entry_free);
			return -E2BIG;
		}
		dtab->items++;
	}

	hlist_add_head_rcu(&dev->index_hlist,
			   dev_map_index_hash(dtab, idx));
	spin_unlock_irqrestore(&dtab->index_lock, flags);

	if (old_dev)
		call_rcu(&old_dev->rcu, __dev_map_entry_free);

	return 0;
}

static int dev_map_hash_update_elem(struct bpf_map *map, void *key, void *value,
				   u64 map_flags)
{
	return __dev_map_hash_update_elem(current->nsproxy->net_ns,
					 map, key, value, map_flags);
}
