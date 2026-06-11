from pathlib import Path
from typing import Dict, Iterable, List, Tuple


COLORS = ["#276FBF", "#D64550", "#2E8B57", "#F2A541", "#6A4C93", "#4D908E", "#577590"]


def _escape(text) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_bar_chart_svg(
    path: Path,
    title: str,
    values: Dict[str, int],
    width: int = 900,
    height: int = 460,
) -> None:
    items: List[Tuple[str, int]] = [(str(k), int(v)) for k, v in values.items() if int(v) >= 0]
    items = items[:12]
    max_value = max([v for _, v in items] or [1])
    margin_left = 170
    margin_top = 70
    bar_height = 24
    gap = 12
    plot_width = width - margin_left - 70
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="34" text-anchor="middle" font-family="Arial" font-size="22" font-weight="700">{_escape(title)}</text>',
    ]
    for idx, (label, value) in enumerate(items):
        y = margin_top + idx * (bar_height + gap)
        bar_width = 1 if max_value == 0 else int((value / max_value) * plot_width)
        color = COLORS[idx % len(COLORS)]
        svg.append(f'<text x="{margin_left - 12}" y="{y + 18}" text-anchor="end" font-family="Arial" font-size="13">{_escape(label)}</text>')
        svg.append(f'<rect x="{margin_left}" y="{y}" width="{bar_width}" height="{bar_height}" fill="{color}"/>')
        svg.append(f'<text x="{margin_left + bar_width + 8}" y="{y + 18}" font-family="Arial" font-size="13">{value}</text>')
    svg.append("</svg>")
    path.write_text("\n".join(svg), encoding="utf-8")


def write_confusion_matrix_svg(
    path: Path,
    title: str,
    labels: Iterable,
    matrix: List[List[int]],
    width: int = 620,
    height: int = 560,
) -> None:
    labels = [str(label) for label in labels]
    n = len(labels)
    cell = 80 if n <= 4 else 54
    x0 = 170
    y0 = 110
    max_value = max([max(row) for row in matrix] or [1])
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="34" text-anchor="middle" font-family="Arial" font-size="21" font-weight="700">{_escape(title)}</text>',
        f'<text x="{x0 + n * cell / 2}" y="78" text-anchor="middle" font-family="Arial" font-size="14">Predicted</text>',
        f'<text x="35" y="{y0 + n * cell / 2}" transform="rotate(-90 35 {y0 + n * cell / 2})" text-anchor="middle" font-family="Arial" font-size="14">Actual</text>',
    ]
    for j, label in enumerate(labels):
        svg.append(f'<text x="{x0 + j * cell + cell / 2}" y="{y0 - 14}" text-anchor="middle" font-family="Arial" font-size="12">{_escape(label)}</text>')
    for i, label in enumerate(labels):
        svg.append(f'<text x="{x0 - 14}" y="{y0 + i * cell + cell / 2 + 4}" text-anchor="end" font-family="Arial" font-size="12">{_escape(label)}</text>')
        for j, value in enumerate(matrix[i]):
            intensity = 0 if max_value == 0 else value / max_value
            blue = int(245 - 150 * intensity)
            color = f"rgb({blue},{blue + 5},255)"
            x = x0 + j * cell
            y = y0 + i * cell
            svg.append(f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" fill="{color}" stroke="#333333"/>')
            svg.append(f'<text x="{x + cell / 2}" y="{y + cell / 2 + 5}" text-anchor="middle" font-family="Arial" font-size="14" font-weight="700">{value}</text>')
    svg.append("</svg>")
    path.write_text("\n".join(svg), encoding="utf-8")
