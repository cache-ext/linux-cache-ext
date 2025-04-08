# MGLRU

- Multiple generations. Each generation is a collection of pages with similar
  access recency.
- Gen counter stored in `folio->flags` (from `MIN_NR_GENS` to `MAX_NR_GENS`).
- Each generation has multiple tiers. Tier counter stores order_base_2(accesses).
- Moving across tiers is just an atomic op to `folio->flags`.
- PID controller monitors refault over all tiers and decides which ones to evict.
- Desired effect: Balance refault pct between file/anon and proportional to swappiness.
- Per-list state:
  - `max_seq`: Youngest generation
  - `min_seq`: Oldest generation
- Per-folio state:
  - `gen_counter`: Which generation is this page in? Young pages get `(max_seq % MAX_NR_GENS) + 1`

Aging:
- Increase `max_seq` (why???)

Eviction:
- Consume old generations.
- Increment `min_seq` when `lrugen->folios[ min_seq % MAX_NR_GENS ]` becomes empty.



order_base_2(N): Highest power of 2 less or equal to N.


## Code Notes

Eviction:
1. `try_to_shrink_lruvec`
2. `evict_folios` (gets lruvec lock)
3. `isolate_folios`: Decide tier and type (anon/file). Uses the PID controller to decide.
4. `scan_folios`: Scans the lowest gen (`lru_gen_from_seq(lrugen->min_seq[type])`).
    1. `sort_folio`: Check if we need to promote / handle edge cases.
       This also promotes to the next gen any folios with tier bigger than the
       tier decided by step 3 above.
    2. `isolate_folio`: Actual eviction if the previous step failed.
    3. If both of the above fail, just skip these folios and add them back in the end.

Aging:
(happens during eviction)
1. `try_to_shrink_lruvec`
2. `get_nr_to_scan`
3. `should_run_aging` / `try_to_inc_max_seq`

Tiers:
- The max number of tiers is currently set to 4 (`MAX_NR_TIERS`)
- Each page keeps track of refs through a file descriptor (`folio_lru_refs()`).
    - This info is stored in the page flags and updated with a CAS instruction.
- The tier of a page is given by its refs (`lru_tier_from_refs()`).
