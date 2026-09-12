use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Row, Table};

pub fn render(frame: &mut Frame, area: Rect) {
    let header = Row::new(["Name", "Size", "Description"])
        .style(Style::new().bold())
        .bottom_margin(1);

    let rows: Vec<Row> = Vec::new();

    let table = Table::new(rows, [20, 10, 30])
        .header(header);



    frame.render_widget(table, area);
}