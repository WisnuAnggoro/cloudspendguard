# Human evaluation: survey instrument

Purpose: the qualitative metric of Unit 6 (plan Week 6, RAID R-03). Five to eight engineers rate the 20
remediation cards in `cards-top20.md`, which `csg run --sample --top 20 --format markdown` produced from the
bundled sample account. Build this as a Google Form (one section per block) and export the answers as CSV.

## Instructions shown to the respondent

You will see 20 findings from a cloud account analysis tool. Each shows what was found, a priority score, and a
suggested fix. Rate each statement from 1 (strongly disagree) to 5 (strongly agree). The data is synthetic.
Answers are anonymous. Nothing you rate is applied to a real system.

## Block A: respondent background (once)

| Id | Question | Type |
|---|---|---|
| A1 | Years of experience with AWS | 0-1, 2-4, 5-9, 10+ |
| A2 | Main role | DevOps/SRE, Backend, Security, FinOps, Other |
| A3 | Have you used tfsec, Checkov, or Infracost? | Yes/No |

## Block B: per card (repeat for cards 1 to 20)

| Id | Statement | Scale |
|---|---|---|
| B1 Clarity | I understand what is wrong and on which resource. | 1 to 5 |
| B2 Actionability | The suggested fix is specific enough that I could carry it out. | 1 to 5 |
| B3 Correctness | The suggested fix is technically correct and safe to try in a test account. | 1 to 5 |
| B4 Priority | The position of this item in the list feels reasonable. | 1 to 5 |

To keep the form short, give each respondent a block of 10 cards (cards 1 to 10 or 11 to 20, alternating), so
every card collects at least 3 ratings from 5 respondents.

## Block C: whole report (once, based on `docs/sample-report.html`)

| Id | Statement | Scale |
|---|---|---|
| C1 | The report was easy to scan; I found the most important item quickly. | 1 to 5 |
| C2 | The score breakdown (S, R, B) helped me trust the order. | 1 to 5 |
| C3 | I would use this report in my weekly review. | 1 to 5 |
| C4 | I would trust a tool that keeps all data on my machine more than one that does not. | 1 to 5 |
| C5 | What was confusing or missing? | Free text |

## Analysis plan (decided before collecting data)

- Report n, the mean, the median, and the share of favorable answers (4 or 5) for B1 to B4 and C1 to C4.
- Treat a mean below 3.5 or a favorable share below 70% as a weak area to fix.
- With 5 to 8 respondents this is exploratory, not statistically conclusive; report it that way.
- Fallback (RAID R-03): if fewer than 5 respond, add 2 heuristic reviewers using Nielsen's ten heuristics and
  say so in the report.

## Collecting and summarizing

1. Export the responses to `docs/survey/responses.csv` using the columns of `responses-template.csv`
   (one row per respondent and card, `card` empty for C items).
2. Run `python3 scripts/survey_summary.py docs/survey/responses.csv`. It prints a Markdown table and, if
   matplotlib is installed, writes `docs/survey/survey-chart.png`.

The template contains no real answers. Do not report survey numbers until real respondents have answered.
