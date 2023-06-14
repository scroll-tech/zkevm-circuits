trait CellManagerStrategy {
    fn query_top_aligned_cell(&mut self, cell_type: CellType) -> Cell<F>;
    fn query_cell(&mut self, cell_type: CellType) -> Cell<F>;
    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>>;
    fn columns(&self) -> &[CellColumn<F>];
    fn get_width(&self) -> usize;
    fn get_height(&self) -> usize;
}
