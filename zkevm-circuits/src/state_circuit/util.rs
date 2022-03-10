let q_tag_is = |meta: &mut VirtualCells<F>, tag_value: usize| {
    let tag_cur = meta.query_advice(tag, Rotation::cur());
    generate_lagrange_base_polynomial(
        tag_cur,
        tag_value,
        RwTableTag::iter().map(|tag| tag as usize),
    )
};


fn q_memory(meta: &mut VirtualCells<F>) {
    q_tag_is(meta, MEMORY_TAG)
}

fn q_stack(meta: &mut VirtualCells<F>) {
    q_tag_is(meta, STACK_TAG)
}

fn q_storage(meta: &mut VirtualCells<F>) {
    q_tag_is(meta, STORAGE_TAG)
};
