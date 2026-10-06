// Package anomaly implements the multi-signal cost-anomaly detector that is
// part of module M5 (docs/architecture.md). Each CUR time series (one per
// service and team tag) is decomposed with STL, the residual is scored with a
// robust z-score, and an Isolation Forest independently scores the same days.
// A day is reported only when both signals agree, which trades a little
// recall for far fewer false alarms on short, noisy billing histories.
//
// References:
//   - Cleveland, R. B., Cleveland, W. S., McRae, J. E., & Terpenning, I.
//     (1990). STL: A seasonal-trend decomposition procedure based on loess.
//     Journal of Official Statistics, 6(1), 3-73.
//   - Iglewicz, B., & Hoaglin, D. C. (1993). How to detect and handle
//     outliers. ASQC Quality Press. (modified z-score, threshold 3.5)
//   - Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). Isolation forest. In
//     Proc. IEEE ICDM (pp. 413-422). https://doi.org/10.1109/ICDM.2008.17
//
// Added in Unit 5 (v0.3.0-algo).
package anomaly

import (
	"errors"
	"math"
	"sort"
)

// ErrSeriesTooShort is returned when a series has fewer than two full
// seasonal periods plus one point, the minimum STL needs to separate
// seasonality from trend.
var ErrSeriesTooShort = errors.New("anomaly: series shorter than 2 x period + 1")

// STLConfig holds the STL smoothing parameters. Zero values select the
// defaults recommended by Cleveland et al. (1990).
type STLConfig struct {
	Period         int // seasonal period n(p); 7 for daily billing data
	SeasonalSpan   int // n(s), odd, >= 7
	TrendSpan      int // n(t), odd
	LowPassSpan    int // n(l), odd
	InnerLoops     int // n(i)
	RobustnessIter int // n(o); > 0 enables the robust (outlier-resistant) fit
}

// Decomposition is y = Trend + Seasonal + Residual, element by element.
type Decomposition struct {
	Trend, Seasonal, Residual []float64
}

func (c STLConfig) withDefaults() STLConfig {
	if c.Period < 2 {
		c.Period = 7
	}
	if c.SeasonalSpan < 7 {
		c.SeasonalSpan = 7
	}
	c.SeasonalSpan = nextOdd(float64(c.SeasonalSpan))
	if c.LowPassSpan <= 0 {
		c.LowPassSpan = nextOdd(float64(c.Period))
	}
	if c.TrendSpan <= 0 {
		c.TrendSpan = nextOdd(1.5 * float64(c.Period) / (1 - 1.5/float64(c.SeasonalSpan)))
	}
	if c.InnerLoops <= 0 {
		c.InnerLoops = 2
	}
	if c.RobustnessIter < 0 {
		c.RobustnessIter = 0
	}
	return c
}

func nextOdd(x float64) int {
	n := int(math.Ceil(x))
	if n%2 == 0 {
		n++
	}
	return n
}

// STL decomposes y with the robust STL procedure. Robustness weights stop a
// short spike from leaking into the trend or seasonal components, which is
// exactly the property an anomaly detector needs: the spike must stay in the
// residual where the z-score can see it.
func STL(y []float64, cfg STLConfig) (Decomposition, error) {
	cfg = cfg.withDefaults()
	n, np := len(y), cfg.Period
	if n < 2*np+1 {
		return Decomposition{}, ErrSeriesTooShort
	}
	trend := make([]float64, n)
	seasonal := make([]float64, n)
	rw := ones(n)
	for outer := 0; outer <= cfg.RobustnessIter; outer++ {
		for inner := 0; inner < cfg.InnerLoops; inner++ {
			// Step 1: detrend.
			detr := make([]float64, n)
			for i := range y {
				detr[i] = y[i] - trend[i]
			}
			// Step 2: smooth each cycle-subseries, extended one period each side.
			c := make([]float64, n+2*np)
			for k := 0; k < np; k++ {
				var xs, ys, ws []float64
				for i := k; i < n; i += np {
					xs = append(xs, float64(len(xs)))
					ys = append(ys, detr[i])
					ws = append(ws, rw[i])
				}
				m := len(xs)
				for j := -1; j <= m; j++ {
					c[(j+1)*np+k] = loess(xs, ys, ws, cfg.SeasonalSpan, float64(j))
				}
			}
			// Step 3: low-pass filter of the cycle-subseries.
			low := movingAverage(movingAverage(movingAverage(c, np), np), 3)
			low = loessSeries(low, nil, cfg.LowPassSpan)
			// Step 4: detrend the smoothed cycle-subseries.
			for i := 0; i < n; i++ {
				seasonal[i] = c[np+i] - low[i]
			}
			// Steps 5 and 6: deseasonalize and smooth the trend.
			deseas := make([]float64, n)
			for i := range y {
				deseas[i] = y[i] - seasonal[i]
			}
			trend = loessSeries(deseas, rw, cfg.TrendSpan)
		}
		if outer < cfg.RobustnessIter {
			rw = robustnessWeights(y, trend, seasonal)
		}
	}
	resid := make([]float64, n)
	for i := range y {
		resid[i] = y[i] - trend[i] - seasonal[i]
	}
	return Decomposition{Trend: trend, Seasonal: seasonal, Residual: resid}, nil
}

// robustnessWeights applies the bisquare function to |R| / (6 * median|R|).
func robustnessWeights(y, trend, seasonal []float64) []float64 {
	n := len(y)
	abs := make([]float64, n)
	for i := range y {
		abs[i] = math.Abs(y[i] - trend[i] - seasonal[i])
	}
	h := 6 * median(abs)
	w := make([]float64, n)
	for i, r := range abs {
		if h == 0 {
			// More than half of the residuals are exactly zero (a flat
			// series). Points that deviate at all are the outliers.
			if r == 0 {
				w[i] = 1
			}
			continue
		}
		u := r / h
		if u < 1 {
			w[i] = (1 - u*u) * (1 - u*u)
		}
	}
	return w
}

// loessSeries smooths an evenly spaced series at every index.
func loessSeries(y, w []float64, span int) []float64 {
	xs := make([]float64, len(y))
	for i := range xs {
		xs[i] = float64(i)
	}
	if w == nil {
		w = ones(len(y))
	}
	out := make([]float64, len(y))
	for i := range y {
		out[i] = loess(xs, y, w, span, float64(i))
	}
	return out
}

// loess fits a locally weighted linear regression at x0 using the span
// nearest points (tricube weights times robustness weights). xs must be
// sorted ascending. When span exceeds len(xs) the neighbourhood is widened
// as in Cleveland et al. (1990), which is what makes extrapolation to the
// ends of short cycle-subseries stable.
func loess(xs, ys, rw []float64, span int, x0 float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	q := span
	if q > n {
		q = n
	}
	lo := 0
	for lo+q < n && x0-xs[lo] > xs[lo+q]-x0 {
		lo++
	}
	hi := lo + q - 1
	h := math.Max(x0-xs[lo], xs[hi]-x0)
	if span > n {
		h += float64(span-n) / 2
	}
	var sw, sx, sy float64
	w := make([]float64, n)
	for i := lo; i <= hi; i++ {
		d := math.Abs(xs[i] - x0)
		if h > 0 && d >= 0.999*h {
			continue
		}
		u := 0.0
		if h > 0 {
			u = d / h
		}
		t := 1 - u*u*u // tricube weight (1 - u^3)^3
		w[i] = t * t * t * rw[i]
		sw += w[i]
		sx += w[i] * xs[i]
		sy += w[i] * ys[i]
	}
	if sw <= 0 {
		return mean(ys[lo : hi+1])
	}
	xm, ym := sx/sw, sy/sw
	var num, den float64
	for i := lo; i <= hi; i++ {
		num += w[i] * (xs[i] - xm) * (ys[i] - ym)
		den += w[i] * (xs[i] - xm) * (xs[i] - xm)
	}
	slope := 0.0
	if rng := xs[hi] - xs[lo]; den > 1e-12*rng*rng {
		slope = num / den
	}
	return ym + slope*(x0-xm)
}

func movingAverage(x []float64, k int) []float64 {
	if len(x) < k {
		return nil
	}
	out := make([]float64, len(x)-k+1)
	var s float64
	for i := 0; i < k; i++ {
		s += x[i]
	}
	out[0] = s / float64(k)
	for i := k; i < len(x); i++ {
		s += x[i] - x[i-k]
		out[i-k+1] = s / float64(k)
	}
	return out
}

func ones(n int) []float64 {
	w := make([]float64, n)
	for i := range w {
		w[i] = 1
	}
	return w
}

func mean(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	var s float64
	for _, v := range x {
		s += v
	}
	return s / float64(len(x))
}

func median(x []float64) float64 {
	if len(x) == 0 {
		return 0
	}
	s := append([]float64(nil), x...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}
