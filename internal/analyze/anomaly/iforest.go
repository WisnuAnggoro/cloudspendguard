package anomaly

import (
	"math"
	"math/rand/v2"
)

// MinScaleUSD is the smallest dispersion RobustZ will divide by: one cent,
// the resolution that matters on an invoice. Without it, a flat billing
// series leaves STL residuals of about 1e-8 (floating-point noise), the MAD
// collapses to that noise, and ordinary days score z in the millions.
const MinScaleUSD = 0.01

// RobustZ returns the modified z-score of every value (Iglewicz & Hoaglin,
// 1993): 0.6745 * (x - median) / MAD. Billing series are often flat for most
// of the month, which makes the MAD (near) zero; the mean absolute deviation,
// scaled by 1.2533 so it estimates the same standard deviation, is used
// instead. Both are floored at MinScaleUSD.
func RobustZ(x []float64) []float64 {
	med := median(x)
	dev := make([]float64, len(x))
	for i, v := range x {
		dev[i] = math.Abs(v - med)
	}
	z := make([]float64, len(x))
	scale := median(dev) / 0.6745
	if scale < MinScaleUSD {
		scale = 1.2533 * mean(dev)
	}
	if scale < MinScaleUSD {
		scale = MinScaleUSD
	}
	for i, v := range x {
		z[i] = (v - med) / scale
	}
	return z
}

// Forest is an Isolation Forest (Liu et al., 2008). Anomalies are few and
// different, so random axis-parallel splits isolate them in fewer steps than
// normal points; the average path length becomes the anomaly score.
type Forest struct {
	trees      []*node
	sampleSize int
}

type node struct {
	feature     int
	split       float64
	left, right *node
	size        int // number of training points at an external node
}

// ForestConfig controls training. Zero values select the defaults from the
// original paper: 100 trees, sub-samples of 256 points.
type ForestConfig struct {
	Trees      int
	SampleSize int
	Seed       uint64 // fixed seed, so results are reproducible run to run
}

// Fit trains a forest on rows of equal-length feature vectors.
func Fit(data [][]float64, cfg ForestConfig) *Forest {
	if cfg.Trees <= 0 {
		cfg.Trees = 100
	}
	if cfg.SampleSize <= 0 {
		cfg.SampleSize = 256
	}
	if cfg.SampleSize > len(data) {
		cfg.SampleSize = len(data)
	}
	rng := rand.New(rand.NewPCG(cfg.Seed, 0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic sampling, not cryptography
	limit := int(math.Ceil(math.Log2(math.Max(float64(cfg.SampleSize), 2))))
	f := &Forest{sampleSize: cfg.SampleSize}
	for t := 0; t < cfg.Trees; t++ {
		idx := rng.Perm(len(data))[:cfg.SampleSize]
		sample := make([][]float64, len(idx))
		for i, j := range idx {
			sample[i] = data[j]
		}
		f.trees = append(f.trees, grow(sample, 0, limit, rng))
	}
	return f
}

func grow(x [][]float64, depth, limit int, rng *rand.Rand) *node {
	if depth >= limit || len(x) <= 1 {
		return &node{size: len(x)}
	}
	dims := len(x[0])
	// Pick a random feature that still varies; give up after a few tries.
	for attempt := 0; attempt < 2*dims; attempt++ {
		q := rng.IntN(dims)
		lo, hi := x[0][q], x[0][q]
		for _, row := range x[1:] {
			lo, hi = math.Min(lo, row[q]), math.Max(hi, row[q])
		}
		if hi-lo <= 1e-12 {
			continue
		}
		p := lo + rng.Float64()*(hi-lo)
		var l, r [][]float64
		for _, row := range x {
			if row[q] < p {
				l = append(l, row)
			} else {
				r = append(r, row)
			}
		}
		return &node{feature: q, split: p, left: grow(l, depth+1, limit, rng), right: grow(r, depth+1, limit, rng)}
	}
	return &node{size: len(x)}
}

// Score returns s(x) = 2^(-E[h(x)] / c(psi)) in (0, 1]. Values near 1 are
// anomalous; values at or below 0.5 are normal.
func (f *Forest) Score(x []float64) float64 {
	if f == nil || len(f.trees) == 0 {
		return 0
	}
	var total float64
	for _, t := range f.trees {
		total += pathLength(t, x, 0)
	}
	avg := total / float64(len(f.trees))
	c := avgPathLength(f.sampleSize)
	if c == 0 {
		return 0
	}
	return math.Pow(2, -avg/c)
}

func pathLength(n *node, x []float64, depth int) float64 {
	if n.left == nil {
		return float64(depth) + avgPathLength(n.size)
	}
	if x[n.feature] < n.split {
		return pathLength(n.left, x, depth+1)
	}
	return pathLength(n.right, x, depth+1)
}

// avgPathLength is c(n), the average path length of an unsuccessful binary
// search tree lookup, used to normalize path lengths.
func avgPathLength(n int) float64 {
	switch {
	case n <= 1:
		return 0
	case n == 2:
		return 1
	}
	h := math.Log(float64(n-1)) + 0.5772156649
	return 2*h - 2*float64(n-1)/float64(n)
}
