package anomaly

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

// confusion counts day-level detections against the injected ground truth.
type confusion struct{ tp, fp, fn int }

func (c confusion) precision() float64 { return ratio(c.tp, c.tp+c.fp) }
func (c confusion) recall() float64    { return ratio(c.tp, c.tp+c.fn) }
func (c confusion) f1() float64 {
	p, r := c.precision(), c.recall()
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func (c *confusion) add(pred, truth bool) {
	switch {
	case pred && truth:
		c.tp++
	case pred && !truth:
		c.fp++
	case !pred && truth:
		c.fn++
	}
}

// synthetic returns a 30-day series shaped like real billing data: a level,
// a slow trend, a weekday/weekend pattern, multiplicative noise, and (in
// about half of the series) one or two injected spike days.
func synthetic(rng *rand.Rand) (Series, []bool) {
	level := 5 + rng.Float64()*195
	weekend := rng.Float64() * 0.6 // weekend dip of 0 to 60%
	slope := (rng.Float64() - 0.5) * 0.01 * level
	noise := 0.01 + rng.Float64()*0.03
	truth := make([]bool, 30)
	if rng.Intn(2) == 0 {
		for k := 0; k < 1+rng.Intn(2); k++ {
			truth[3+rng.Intn(24)] = true
		}
	}
	s := Series{Key: "synthetic"}
	day0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		d := day0.AddDate(0, 0, i)
		v := level + slope*float64(i)
		if wd := d.Weekday(); wd == time.Saturday || wd == time.Sunday {
			v *= 1 - weekend
		}
		v *= 1 + rng.NormFloat64()*noise
		if truth[i] {
			v += level * (0.5 + rng.Float64()*2.5) // +50% to +300%
		}
		s.Points = append(s.Points, Point{Day: d, Observed: v})
	}
	return s, truth
}

// TestDetectionQuality is the output-validation experiment reported in the
// Unit 5 write-up. It compares four detectors on 400 seeded synthetic
// series (12,000 days): a naive 3-sigma rule on raw spend, the STL residual
// z-score alone, the Isolation Forest alone, and the shipped AND-combination.
// The z-only and forest-only rows use the same materiality filter as the
// shipped detector, so the comparison isolates the statistical signal.
// Run with -v to print the table.
func TestDetectionQuality(t *testing.T) {
	rng := rand.New(rand.NewSource(5910))
	cfg := Config{}.withDefaults()
	var naive, zOnly, forestOnly, both confusion
	for n := 0; n < 400; n++ {
		s, truth := synthetic(rng)
		var mean, sd float64
		for _, p := range s.Points {
			mean += p.Observed
		}
		mean /= float64(len(s.Points))
		for _, p := range s.Points {
			sd += (p.Observed - mean) * (p.Observed - mean)
		}
		sd = math.Sqrt(sd / float64(len(s.Points)))
		if err := Score(&s, cfg); err != nil {
			t.Fatal(err)
		}
		for i, p := range s.Points {
			excess := material(p, cfg)
			naive.add(p.Observed > mean+3*sd, truth[i])
			zOnly.add(p.Z >= cfg.ZThreshold && excess, truth[i])
			forestOnly.add(p.ForestScore >= cfg.ForestThreshold && excess, truth[i])
			both.add(p.Anomalous, truth[i])
		}
	}
	t.Logf("%-28s %9s %9s %6s %5s %5s %5s", "detector", "precision", "recall", "F1", "TP", "FP", "FN")
	for _, r := range []struct {
		name string
		c    confusion
	}{{"naive 3-sigma on raw spend", naive}, {"STL + robust z only", zOnly}, {"Isolation Forest only", forestOnly}, {"STL z AND forest (shipped)", both}} {
		t.Logf("%-28s %9.3f %9.3f %6.3f %5d %5d %5d", r.name, r.c.precision(), r.c.recall(), r.c.f1(), r.c.tp, r.c.fp, r.c.fn)
	}
	if both.precision() < 0.9 || both.recall() < 0.8 {
		t.Fatalf("shipped detector: precision %.3f, recall %.3f; want >= 0.90 and >= 0.80", both.precision(), both.recall())
	}
	if both.f1() < naive.f1() || both.precision() < zOnly.precision() || both.precision() < forestOnly.precision() {
		t.Fatal("the combination must beat the naive baseline and be at least as precise as either signal alone")
	}
}
