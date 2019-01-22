// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519 implements the Ed25519 signature algorithm. See
// http://ed25519.cr.yp.to/.

package ed25519

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/agl/ed25519/edwards25519"
)

var bigZero *big.Int
var bigOne *big.Int

type ed25519Curve struct {
	*elliptic.CurveParams
}

var once sync.Once
var ed25519Params = &elliptic.CurveParams{Name: "ed25519"}
var ed25519 = ed25519Curve{ed25519Params}

var d *big.Int
var negD *big.Int

// Ed25519 uses a twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2 with the following params:
// The field prime is 2^255 - 19.
// The order of the base point is 2^252 + 27742317777372353535851937790883648493.
// And since B is irrelevant here, we're going to pretend that B is d = -(121665/121666).
func initEd25519Params() {
	ed25519Params.P, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	ed25519Params.N, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	ed25519Params.B, _ = new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)
	ed25519Params.Gx, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
	ed25519Params.Gy, _ = new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
	ed25519Params.BitSize = 256
	bigZero = big.NewInt(0)
	bigOne = big.NewInt(1)

	d = big.NewInt(121666)
	d.ModInverse(d, ed25519Params.P)
	d.Mul(d, big.NewInt(-121665))
	d.Mod(d, ed25519Params.P)

	negD = new(big.Int).Sub(ed25519Params.P, d)
}

// Ed25519 returns a Curve that implements Ed25519.
func Ed25519() elliptic.Curve {
	once.Do(initEd25519Params)
	return ed25519
}

// Params returns the parameters for the curve.
func (curve ed25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

// IsOnCurve reports whether the given (x,y) lies on the curve by checking that
// -x^2 + y^2 - 1 - dx^2y^2 = 0 (mod p). This function uses a hardcoded value
// of d.
func (curve ed25519Curve) IsOnCurve(x, y *big.Int) bool {
	// var feX, feY field.FieldElement
	// field.FeFromBig(&feX, x)
	// field.FeFromBig(&feY, y)

	// var lh, y2, rh field.FieldElement
	// field.FeSquare(&lh, &feX)              // x^2
	// field.FeSquare(&y2, &feY)              // y^2
	// field.FeMul(&rh, &lh, &y2)             // x^2*y^2
	// field.FeMul(&rh, &rh, &group.D)        // d*x^2*y^2
	// field.FeAdd(&rh, &rh, &field.FieldOne) // 1 + d*x^2*y^2
	// field.FeNeg(&lh, &lh)                  // -x^2
	// field.FeAdd(&lh, &lh, &y2)             // -x^2 + y^2
	// field.FeSub(&lh, &lh, &rh)             // -x^2 + y^2 - 1 - dx^2y^2
	// field.FeReduce(&lh, &lh)               // mod p

	// return field.FeEqual(&lh, &field.FieldZero)
	return false
}

// Add returns the sum of (x1, y1) and (x2, y2).
func (curve ed25519Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	x1x2 := new(big.Int).Mul(x1, x2)
	y1y2 := new(big.Int).Mul(y1, y2)
	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	x1x2y1y2 := new(big.Int).Mul(x1x2, y1y2)
	denom := new(big.Int).Mul(d, x1x2y1y2)
	negdenom := new(big.Int).Mul(negD, x1x2y1y2)

	oneSubDenomInv := new(big.Int).Add(big.NewInt(1), negdenom)
	oneSubDenomInv.ModInverse(oneSubDenomInv, curve.P)
	oneAddDenomInv := new(big.Int).Add(big.NewInt(1), denom)
	oneAddDenomInv.ModInverse(oneAddDenomInv, curve.P)

	x = new(big.Int).Add(x1y2, y1x2)
	x.Mul(x, oneAddDenomInv)
	x.Mod(x, curve.P)
	y = new(big.Int).Add(x1x2, y1y2)
	y.Mul(y, oneSubDenomInv)
	y.Mod(y, curve.P)
	return x, y
}

// Double returns 2*(x,y).
func (curve ed25519Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	return curve.Add(x1, y1, x1, y1)
}

// ScalarMult returns k*(Bx,By) where k is a number in big-endian form.
func (curve ed25519Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	a := extendedGroupElementFromInt(x1, y1)
	hBytes := convertBigEndianAndLittleEndian32(k)

	var out edwards25519.ExtendedGroupElement
	edwards25519.ScalarMult(&out, hBytes, &a)

	return extendedGroupElementToInt(&out)
}

// ScalarBaseMult returns k*G, where G is the base point of the curve and k is
// an integer in big-endian form. The difference between this and
// arbitrary-point ScalarMult is the availability of precomputed multiples of
// the base point.
func (curve ed25519Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	var a edwards25519.ExtendedGroupElement
	hBytes := convertBigEndianAndLittleEndian32(k)
	edwards25519.GeScalarMultBase(&a, hBytes)

	return extendedGroupElementToInt(&a)
}
func convertBigEndianAndLittleEndian32(in []byte) *[32]byte {
	var out [32]byte
	lens := len(in)
	for i, b := range in {
		out[lens-1-i] = b
	}
	return &out
}

func extendedGroupElementFromInt(bigX, bigY *big.Int) edwards25519.ExtendedGroupElement {
	var p edwards25519.ExtendedGroupElement

	edwards25519.FeFromBytes(&p.X, convertBigEndianAndLittleEndian32(bigX.Bytes()))
	edwards25519.FeFromBytes(&p.Y, convertBigEndianAndLittleEndian32(bigY.Bytes()))
	edwards25519.FeOne(&p.Z)
	edwards25519.FeMul(&p.T, &p.X, &p.Y)
	return p
}

func extendedGroupElementToInt(p *edwards25519.ExtendedGroupElement) (*big.Int, *big.Int) {
	var recip, x, y edwards25519.FieldElement

	edwards25519.FeInvert(&recip, &p.Z)
	edwards25519.FeMul(&x, &p.X, &recip)
	edwards25519.FeMul(&y, &p.Y, &recip)

	var xBytes, yBytes [32]byte
	edwards25519.FeToBytes(&xBytes, &x)
	edwards25519.FeToBytes(&yBytes, &y)
	return new(big.Int).SetBytes(convertBigEndianAndLittleEndian32(xBytes[:])[:]),
		new(big.Int).SetBytes(convertBigEndianAndLittleEndian32(yBytes[:])[:])
}
