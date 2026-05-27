# Paper Directory

本目录保存论文材料。

## Files

- `draft_en.md`: 英文完整草稿。
- `draft_zh_outline.md`: 中文论文大纲。
- `main.tex`: LaTeX 骨架，适合后续迁移到 ACM/IEEE 模板。
- `references.bib`: BibTeX 引用脚手架。
- `related_work_matrix.md`: 相关工作差异矩阵。
- `figures/`: Mermaid 图示。

## Compile skeleton

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

当前 `main.tex` 是结构骨架，不是最终投稿模板。正式投稿时应迁移到目标会议模板，并补齐实验结果、统计检验和 artifact appendix。
