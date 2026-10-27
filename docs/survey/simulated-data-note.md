# Illustrative Survey Data

`simulated-responses.csv` is synthetic example data, not a Google Form export.
It reconstructs one possible set of 200 ratings that matches the four example
aggregate rows: 50 ratings per item, with means 4.24, 4.04, 3.86, and 3.72 and
favorable percentages 84%, 78%, 72%, and 66%.

The IDs `SIM01` through `SIM05` are fictional. Each is assigned ten example card
ratings per item. That assignment is arbitrary; it does not document real
participants or findings. This file is deliberately separate from `responses.csv`
and must not replace actual response data.

## Caption to include in the DOCX

**Figure 8**

Survey Summary

Note. Values are simulated for demonstration, not collected survey responses.
The example assumes five hypothetical engineers each rating ten cards, giving
50 ratings per item. Favorable responses are ratings of 4 or 5.

The PNG does not carry a simulation label because the disclosure is intended to
appear in the document caption. Keep this note with the figure whenever it is
submitted or shared as an evaluation example. It demonstrates the analysis format,
but does not establish that the planned human evaluation was completed.

## Generate the chart and terminal summary

From the repository root:

```bash
python3 -m pip install matplotlib
python3 scripts/generate_example_survey.py
```

The script prints the summary and writes the labelled example CSV to
`docs/survey/simulated-responses.csv` and the figure to
`docs/survey/fig08-survey-summary.png`. The printed numbers match
Table 4's simulated example.
