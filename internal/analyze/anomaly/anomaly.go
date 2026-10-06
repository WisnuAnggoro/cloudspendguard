package anomaly

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/wisnuanggoro/cloudspendguard/internal/ingest/cur"
	"github.com/wisnuanggoro/cloudspendguard/pkg/models"
)

// RuleID identifies findings produced by this detector.
const RuleID = "COST-ANOMALY-001"

// Config tunes the detector. Zero values select the defaults.
type Config struct {
	STL STLConfig
	// ZThreshold is the modified z-score above which a residual is an
	// outlier. 3.5 is the value recommended by Iglewicz and Hoaglin (1993).
	ZThreshold float64
	// ForestThreshold is the Isolation Forest score above which a day is
	// anomalous. Scores near 0.5 are normal (Liu et al., 2008).
	ForestThreshold float64
	// MinExcessUSD ignores statistically unusual but financially trivial days.
	MinExcessUSD float64
	// MinExcessRatio is the materiality threshold: the excess must also be at
	// least this share of the expected spend. Unit 5 validation finding:
	// with 30 points, robust STL leaves residuals so tight that ordinary 1 to
	// 4% billing noise crossed z = 3.5 on 4.7% of normal days. A 20% floor
	// cut false positives from 120 to 1 (precision 0.712 to 0.997) at the
	// cost of 3 of 296 detected spikes (recall 0.919 to 0.910); see
	// TestDetectionQuality.
	MinExcessRatio float64
	Forest         ForestConfig
}

func (c Config) withDefaults() Config {
	if c.ZThreshold <= 0 {
		c.ZThreshold = 3.5
	}
	if c.ForestThreshold <= 0 {
		c.ForestThreshold = 0.6
	}
	if c.MinExcessUSD <= 0 {
		c.MinExcessUSD = 1
	}
	if c.MinExcessRatio <= 0 {
		c.MinExcessRatio = 0.2
	}
	if c.Forest.Seed == 0 {
		c.Forest.Seed = 5910 // the course code; any fixed value works
	}
	if c.STL.RobustnessIter == 0 {
		c.STL.RobustnessIter = 5
	}
	return c
}

// Point is the per-day result for one series.
type Point struct {
	Day         time.Time
	Observed    float64
	Expected    float64 // trend + seasonal
	Trend       float64
	Seasonal    float64
	Residual    float64
	Z           float64
	ForestScore float64
	Anomalous   bool
}

// Series is one daily cost series, keyed by service and team tag.
type Series struct {
	Key     string // "AmazonEC2/booking"
	Service string
	Team    string
	Region  string
	Points  []Point
}

// BuildSeries aggregates CUR line items into daily cost per service and team
// tag. Missing days between the first and last observation count as zero.
func BuildSeries(records []cur.Record) []Series {
	type acc struct {
		s     *Series
		daily map[time.Time]float64
	}
	byKey := map[string]*acc{}
	var first, last time.Time
	for _, r := range records {
		if r.UsageStartDate.IsZero() {
			continue
		}
		team := r.Tags["team"]
		if team == "" {
			team = "untagged"
		}
		key := r.Service + "/" + team
		a, ok := byKey[key]
		if !ok {
			a = &acc{s: &Series{Key: key, Service: r.Service, Team: team, Region: r.Region}, daily: map[time.Time]float64{}}
			byKey[key] = a
		}
		day := r.UsageStartDate.UTC().Truncate(24 * time.Hour)
		a.daily[day] += r.UnblendedCost
		if first.IsZero() || day.Before(first) {
			first = day
		}
		if day.After(last) {
			last = day
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Series, 0, len(keys))
	for _, k := range keys {
		a := byKey[k]
		for d := first; !d.After(last); d = d.AddDate(0, 0, 1) {
			a.s.Points = append(a.s.Points, Point{Day: d, Observed: a.daily[d]})
		}
		out = append(out, *a.s)
	}
	return out
}

// Score runs both signals over one series in place. Series shorter than
// 2 x period + 1 days are left unscored (ErrSeriesTooShort).
func Score(s *Series, cfg Config) error {
	cfg = cfg.withDefaults()
	y := make([]float64, len(s.Points))
	for i, p := range s.Points {
		y[i] = p.Observed
	}
	dec, err := STL(y, cfg.STL)
	if err != nil {
		return err
	}
	z := RobustZ(dec.Residual)

	// Isolation Forest features: level, residual, and day-over-day change,
	// each min-max scaled so no feature dominates the random splits.
	feats := make([][]float64, len(y))
	for i := range y {
		delta := 0.0
		if i > 0 {
			delta = y[i] - y[i-1]
		}
		feats[i] = []float64{y[i], dec.Residual[i], delta}
	}
	scale(feats)
	forest := Fit(feats, cfg.Forest)

	for i := range s.Points {
		p := &s.Points[i]
		p.Trend, p.Seasonal, p.Residual, p.Z = dec.Trend[i], dec.Seasonal[i], dec.Residual[i], z[i]
		p.Expected = dec.Trend[i] + dec.Seasonal[i]
		p.ForestScore = forest.Score(feats[i])
		// Only spend increases matter for FinOps; a drop is good news.
		p.Anomalous = p.Z >= cfg.ZThreshold && p.ForestScore >= cfg.ForestThreshold && material(*p, cfg)
	}
	return nil
}

// material reports whether a day's excess over the STL expectation is large
// enough to act on, in absolute and in relative terms.
func material(p Point, cfg Config) bool {
	excess := p.Observed - p.Expected
	return excess >= cfg.MinExcessUSD && excess >= cfg.MinExcessRatio*math.Abs(p.Expected)
}

// scale min-max scales each feature column to [0, 1]. Columns whose range is
// below MinScaleUSD are treated as constant; otherwise floating-point noise
// in a flat series is stretched to the full range and the forest isolates
// noise instead of spend.
func scale(rows [][]float64) {
	if len(rows) == 0 {
		return
	}
	for j := range rows[0] {
		lo, hi := math.Inf(1), math.Inf(-1)
		for _, r := range rows {
			lo, hi = math.Min(lo, r[j]), math.Max(hi, r[j])
		}
		for _, r := range rows {
			if hi-lo >= MinScaleUSD {
				r[j] = (r[j] - lo) / (hi - lo)
			} else {
				r[j] = 0
			}
		}
	}
}

// Detector adapts the anomaly pass to the cost.Detector interface shape.
type Detector struct{ Config Config }

// RuleID implements cost.Detector.
func (Detector) RuleID() string { return RuleID }

// Detect scores every series and turns each run of consecutive anomalous days
// (an episode) into one finding.
func (d Detector) Detect(ctx context.Context, records []cur.Record, now time.Time) ([]models.Finding, error) {
	var out []models.Finding
	for _, s := range BuildSeries(records) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := Score(&s, d.Config); err != nil {
			continue // too short to judge; not an error for the caller
		}
		for _, ep := range episodes(s.Points) {
			out = append(out, finding(s, ep, now))
		}
	}
	return out, nil
}

func episodes(points []Point) [][]Point {
	var out [][]Point
	var cur []Point
	for _, p := range points {
		if p.Anomalous {
			cur = append(cur, p)
			continue
		}
		if len(cur) > 0 {
			out = append(out, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

func finding(s Series, ep []Point, now time.Time) models.Finding {
	var excess, expected, observed, maxZ, maxF float64
	for _, p := range ep {
		excess += p.Observed - p.Expected
		expected += p.Expected
		observed += p.Observed
		maxZ = math.Max(maxZ, p.Z)
		maxF = math.Max(maxF, p.ForestScore)
	}
	start, end := ep[0].Day.Format("2006-01-02"), ep[len(ep)-1].Day.Format("2006-01-02")
	when := start
	if end != start {
		when = start + " to " + end
	}
	var tags map[string]string
	if s.Team != "untagged" {
		tags = map[string]string{"team": s.Team}
	}
	sev := models.SeverityMedium
	if excess >= 100 {
		sev = models.SeverityHigh
	}
	return models.Finding{
		ID:     RuleID + ":" + s.Key + ":" + start,
		Kind:   models.KindCost,
		RuleID: RuleID,
		Title:  fmt.Sprintf("Cost anomaly in %s (team %s)", s.Service, s.Team),
		Description: fmt.Sprintf("Spend on %s was USD %.2f against an STL expectation of USD %.2f (USD %.2f above normal; robust z = %.1f, isolation score = %.2f). Both the statistical and the machine-learning signal agree.",
			when, observed, expected, excess, maxZ, maxF),
		Resource: models.ResourceRef{
			Provider: "aws", Service: strings.ToLower(strings.TrimPrefix(s.Service, "Amazon")), ResourceID: s.Key, Region: s.Region, Tags: tags,
		},
		Severity: sev,
		// Treat the excess as avoidable spend for the month. Unexpected spend
		// is also a classic signal of leaked credentials (crypto-mining), so
		// investigating it carries some security value.
		MonthlySavingsUSD:  math.Round(excess*100) / 100,
		RiskReductionScore: 30,
		BlastRadiusScore:   5,
		SuggestedRemediation: &models.Remediation{
			Summary: fmt.Sprintf("Investigate %s: csg query \"SELECT usage_type, resource_id, ROUND(SUM(cost),2) FROM cur WHERE service = '%s' AND usage_start >= '%s' GROUP BY 1, 2 ORDER BY 3 DESC\" and check CloudTrail for the same window.", when, s.Service, start),
			Action:  models.ActionInvestigate,
		},
		DetectedAt: now,
	}
}
