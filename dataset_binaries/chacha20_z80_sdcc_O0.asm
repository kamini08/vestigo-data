;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module chacha20
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _chacha20_encrypt
	.globl _chacha20_block
	.globl _printf
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
	G$chacha20_block$0$0	= .
	.globl	G$chacha20_block$0$0
	C$chacha20.c$12$0_0$35	= .
	.globl	C$chacha20.c$12$0_0$35
;/work/source_code/chacha20.c:12: void chacha20_block(uint32_t out[16], uint32_t const in[16])
;	---------------------------------
; Function chacha20_block
; ---------------------------------
_chacha20_block::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-166
	add	hl, sp
	ld	sp, hl
	C$chacha20.c$17$2_0$36	= .
	.globl	C$chacha20.c$17$2_0$36
;/work/source_code/chacha20.c:17: for (i = 0; i < 16; ++i)
	ld	hl, #0
	add	hl, sp
	ld	-102 (ix), l
	ld	-101 (ix), h
	ld	bc, #0x0000
00104$:
	C$chacha20.c$18$2_0$36	= .
	.globl	C$chacha20.c$18$2_0$36
;/work/source_code/chacha20.c:18: x[i] = in[i];
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, -102 (ix)
	add	a, e
	ld	-6 (ix), a
	ld	a, -101 (ix)
	adc	a, d
	ld	-5 (ix), a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	push	bc
	ld	e, l
	ld	d, h
	ld	hl, #0x00a4
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	bc
	push	bc
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	ld	hl, #0x00a4
	add	hl, sp
	ld	bc, #0x0004
	ldir
	pop	bc
	C$chacha20.c$17$2_0$36	= .
	.globl	C$chacha20.c$17$2_0$36
;/work/source_code/chacha20.c:17: for (i = 0; i < 16; ++i)
	inc	bc
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00104$
	C$chacha20.c$21$2_0$35	= .
	.globl	C$chacha20.c$21$2_0$35
;/work/source_code/chacha20.c:21: for (i = 0; i < 10; i++) {
	ld	-2 (ix), #0x0a
	xor	a, a
	ld	-1 (ix), a
00108$:
	C$chacha20.c$23$3_0$38	= .
	.globl	C$chacha20.c$23$3_0$38
;/work/source_code/chacha20.c:23: QR(x[0], x[4], x[ 8], x[12]); // column 0
	ld	e, -102 (ix)
	ld	d, -101 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x10
	ld	-100 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-99 (ix), a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -6 (ix)
	add	a, c
	ld	-22 (ix), a
	ld	a, -5 (ix)
	adc	a, b
	ld	-21 (ix), a
	ld	a, -4 (ix)
	adc	a, e
	ld	-20 (ix), a
	ld	a, -3 (ix)
	adc	a, d
	ld	-19 (ix), a
	ld	e, -102 (ix)
	ld	d, -101 (ix)
	ld	hl, #0x0090
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x30
	ld	-98 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-97 (ix), a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	ld	a, e
	xor	a, -22 (ix)
	ld	e, a
	ld	a, d
	xor	a, -21 (ix)
	ld	d, a
	ld	a, c
	xor	a, -20 (ix)
	ld	c, a
	ld	a, b
	xor	a, -19 (ix)
	ld	b, a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-4 (ix), e
	ld	-3 (ix), d
	ld	-6 (ix), #0x00
	ld	-5 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -5 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -4 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -3 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -98 (ix)
	ld	d, -97 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x20
	ld	-96 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-95 (ix), a
	ld	l, -96 (ix)
	ld	h, -95 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -14 (ix)
	ld	-10 (ix), a
	ld	a, b
	adc	a, -13 (ix)
	ld	-9 (ix), a
	ld	a, e
	adc	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, d
	adc	a, -11 (ix)
	ld	-7 (ix), a
	ld	e, -96 (ix)
	ld	d, -95 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	xor	a, -10 (ix)
	ld	c, a
	ld	a, b
	xor	a, -9 (ix)
	ld	b, a
	ld	a, e
	xor	a, -8 (ix)
	ld	e, a
	ld	a, d
	xor	a, -7 (ix)
	ld	d, a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-17 (ix), c
	ld	-16 (ix), b
	ld	-15 (ix), e
	ld	-18 (ix), #0x00
	ld	a, #0x04
00147$:
	sla	-17 (ix)
	rl	-16 (ix)
	rl	-15 (ix)
00148$:
	dec	a
	jr	NZ,00147$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00149$:
	srl	d
	rr	e
00150$:
	djnz	00149$
	ld	a, -18 (ix)
	or	a, e
	ld	-6 (ix), a
	ld	a, -17 (ix)
	or	a, d
	ld	-5 (ix), a
	ld	a, -16 (ix)
	or	a, l
	ld	-4 (ix), a
	ld	a, -15 (ix)
	or	a, h
	ld	-3 (ix), a
	ld	e, -100 (ix)
	ld	d, -99 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -22 (ix)
	add	a, -6 (ix)
	ld	-18 (ix), a
	ld	a, -21 (ix)
	adc	a, -5 (ix)
	ld	-17 (ix), a
	ld	a, -20 (ix)
	adc	a, -4 (ix)
	ld	-16 (ix), a
	ld	a, -19 (ix)
	adc	a, -3 (ix)
	ld	-15 (ix), a
	ld	e, -102 (ix)
	ld	d, -101 (ix)
	ld	hl, #0x0094
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -14 (ix)
	xor	a, -18 (ix)
	ld	e, a
	ld	a, -13 (ix)
	xor	a, -17 (ix)
	ld	d, a
	ld	a, -12 (ix)
	xor	a, -16 (ix)
	ld	c, a
	ld	a, -11 (ix)
	xor	a, -15 (ix)
	ld	b, a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-13 (ix), e
	ld	-12 (ix), d
	ld	-11 (ix), c
	ld	-14 (ix), #0x00
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -14 (ix)
	or	a, c
	ld	-94 (ix), a
	ld	a, -13 (ix)
	or	a, b
	ld	-93 (ix), a
	ld	a, -12 (ix)
	or	a, e
	ld	-92 (ix), a
	ld	a, -11 (ix)
	or	a, d
	ld	-91 (ix), a
	ld	e, -98 (ix)
	ld	d, -97 (ix)
	ld	hl, #0x0048
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -10 (ix)
	add	a, -94 (ix)
	ld	-90 (ix), a
	ld	a, -9 (ix)
	adc	a, -93 (ix)
	ld	-89 (ix), a
	ld	a, -8 (ix)
	adc	a, -92 (ix)
	ld	-88 (ix), a
	ld	a, -7 (ix)
	adc	a, -91 (ix)
	ld	-87 (ix), a
	ld	e, -96 (ix)
	ld	d, -95 (ix)
	ld	hl, #0x004c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	xor	a, -90 (ix)
	ld	e, a
	ld	a, -5 (ix)
	xor	a, -89 (ix)
	ld	d, a
	ld	a, -4 (ix)
	xor	a, -88 (ix)
	ld	c, a
	ld	a, -3 (ix)
	xor	a, -87 (ix)
	ld	b, a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00155$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00156$:
	dec	a
	jr	NZ,00155$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, -6 (ix)
	or	a, c
	ld	-86 (ix), a
	ld	a, -5 (ix)
	or	a, b
	ld	-85 (ix), a
	ld	a, -4 (ix)
	or	a, e
	ld	-84 (ix), a
	ld	a, -3 (ix)
	or	a, d
	ld	-83 (ix), a
	ld	e, -100 (ix)
	ld	d, -99 (ix)
	ld	hl, #0x0050
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$24$3_0$38	= .
	.globl	C$chacha20.c$24$3_0$38
;/work/source_code/chacha20.c:24: QR(x[1], x[5], x[ 9], x[13]); // column 1
	ld	a, -102 (ix)
	add	a, #0x04
	ld	-82 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-81 (ix), a
	ld	e, -82 (ix)
	ld	d, -81 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x14
	ld	-80 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-79 (ix), a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -6 (ix)
	add	a, c
	ld	-22 (ix), a
	ld	a, -5 (ix)
	adc	a, b
	ld	-21 (ix), a
	ld	a, -4 (ix)
	adc	a, e
	ld	-20 (ix), a
	ld	a, -3 (ix)
	adc	a, d
	ld	-19 (ix), a
	ld	e, -82 (ix)
	ld	d, -81 (ix)
	ld	hl, #0x0090
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x34
	ld	-78 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-77 (ix), a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	ld	a, e
	xor	a, -22 (ix)
	ld	e, a
	ld	a, d
	xor	a, -21 (ix)
	ld	d, a
	ld	a, c
	xor	a, -20 (ix)
	ld	c, a
	ld	a, b
	xor	a, -19 (ix)
	ld	b, a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-4 (ix), e
	ld	-3 (ix), d
	ld	-6 (ix), #0x00
	ld	-5 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -5 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -4 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -3 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -78 (ix)
	ld	d, -77 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x24
	ld	-76 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-75 (ix), a
	ld	l, -76 (ix)
	ld	h, -75 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -14 (ix)
	ld	-10 (ix), a
	ld	a, b
	adc	a, -13 (ix)
	ld	-9 (ix), a
	ld	a, e
	adc	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, d
	adc	a, -11 (ix)
	ld	-7 (ix), a
	ld	e, -76 (ix)
	ld	d, -75 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	xor	a, -10 (ix)
	ld	c, a
	ld	a, b
	xor	a, -9 (ix)
	ld	b, a
	ld	a, e
	xor	a, -8 (ix)
	ld	e, a
	ld	a, d
	xor	a, -7 (ix)
	ld	d, a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-25 (ix), c
	ld	-24 (ix), b
	ld	-23 (ix), e
	ld	-26 (ix), #0x00
	ld	a, #0x04
00163$:
	sla	-25 (ix)
	rl	-24 (ix)
	rl	-23 (ix)
00164$:
	dec	a
	jr	NZ,00163$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00165$:
	srl	d
	rr	e
00166$:
	djnz	00165$
	ld	a, -26 (ix)
	or	a, e
	ld	-6 (ix), a
	ld	a, -25 (ix)
	or	a, d
	ld	-5 (ix), a
	ld	a, -24 (ix)
	or	a, l
	ld	-4 (ix), a
	ld	a, -23 (ix)
	or	a, h
	ld	-3 (ix), a
	ld	e, -80 (ix)
	ld	d, -79 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -22 (ix)
	add	a, -6 (ix)
	ld	-74 (ix), a
	ld	a, -21 (ix)
	adc	a, -5 (ix)
	ld	-73 (ix), a
	ld	a, -20 (ix)
	adc	a, -4 (ix)
	ld	-72 (ix), a
	ld	a, -19 (ix)
	adc	a, -3 (ix)
	ld	-71 (ix), a
	ld	e, -82 (ix)
	ld	d, -81 (ix)
	ld	hl, #0x005c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -14 (ix)
	xor	a, -74 (ix)
	ld	e, a
	ld	a, -13 (ix)
	xor	a, -73 (ix)
	ld	d, a
	ld	a, -12 (ix)
	xor	a, -72 (ix)
	ld	c, a
	ld	a, -11 (ix)
	xor	a, -71 (ix)
	ld	b, a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-13 (ix), e
	ld	-12 (ix), d
	ld	-11 (ix), c
	ld	-14 (ix), #0x00
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -14 (ix)
	or	a, c
	ld	-70 (ix), a
	ld	a, -13 (ix)
	or	a, b
	ld	-69 (ix), a
	ld	a, -12 (ix)
	or	a, e
	ld	-68 (ix), a
	ld	a, -11 (ix)
	or	a, d
	ld	-67 (ix), a
	ld	e, -78 (ix)
	ld	d, -77 (ix)
	ld	hl, #0x0060
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -10 (ix)
	add	a, -70 (ix)
	ld	-66 (ix), a
	ld	a, -9 (ix)
	adc	a, -69 (ix)
	ld	-65 (ix), a
	ld	a, -8 (ix)
	adc	a, -68 (ix)
	ld	-64 (ix), a
	ld	a, -7 (ix)
	adc	a, -67 (ix)
	ld	-63 (ix), a
	ld	e, -76 (ix)
	ld	d, -75 (ix)
	ld	hl, #0x0064
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	xor	a, -66 (ix)
	ld	e, a
	ld	a, -5 (ix)
	xor	a, -65 (ix)
	ld	d, a
	ld	a, -4 (ix)
	xor	a, -64 (ix)
	ld	c, a
	ld	a, -3 (ix)
	xor	a, -63 (ix)
	ld	b, a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00171$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00172$:
	dec	a
	jr	NZ,00171$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, -6 (ix)
	or	a, c
	ld	-10 (ix), a
	ld	a, -5 (ix)
	or	a, b
	ld	-9 (ix), a
	ld	a, -4 (ix)
	or	a, e
	ld	-8 (ix), a
	ld	a, -3 (ix)
	or	a, d
	ld	-7 (ix), a
	ld	e, -80 (ix)
	ld	d, -79 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$25$3_0$38	= .
	.globl	C$chacha20.c$25$3_0$38
;/work/source_code/chacha20.c:25: QR(x[2], x[6], x[10], x[14]); // column 2
	ld	a, -102 (ix)
	add	a, #0x08
	ld	-62 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-61 (ix), a
	ld	e, -62 (ix)
	ld	d, -61 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x18
	ld	-60 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-59 (ix), a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -6 (ix)
	add	a, c
	ld	-26 (ix), a
	ld	a, -5 (ix)
	adc	a, b
	ld	-25 (ix), a
	ld	a, -4 (ix)
	adc	a, e
	ld	-24 (ix), a
	ld	a, -3 (ix)
	adc	a, d
	ld	-23 (ix), a
	ld	e, -62 (ix)
	ld	d, -61 (ix)
	ld	hl, #0x008c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x38
	ld	-58 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-57 (ix), a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	ld	a, e
	xor	a, -26 (ix)
	ld	e, a
	ld	a, d
	xor	a, -25 (ix)
	ld	d, a
	ld	a, c
	xor	a, -24 (ix)
	ld	c, a
	ld	a, b
	xor	a, -23 (ix)
	ld	b, a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	ld	-14 (ix), #0x00
	ld	-13 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -14 (ix)
	or	a, c
	ld	-6 (ix), a
	ld	a, -13 (ix)
	or	a, b
	ld	-5 (ix), a
	ld	a, -12 (ix)
	or	a, e
	ld	-4 (ix), a
	ld	a, -11 (ix)
	or	a, d
	ld	-3 (ix), a
	ld	e, -58 (ix)
	ld	d, -57 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x28
	ld	-56 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-55 (ix), a
	ld	l, -56 (ix)
	ld	h, -55 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -6 (ix)
	ld	-22 (ix), a
	ld	a, b
	adc	a, -5 (ix)
	ld	-21 (ix), a
	ld	a, e
	adc	a, -4 (ix)
	ld	-20 (ix), a
	ld	a, d
	adc	a, -3 (ix)
	ld	-19 (ix), a
	ld	e, -56 (ix)
	ld	d, -55 (ix)
	ld	hl, #0x0090
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	xor	a, -22 (ix)
	ld	c, a
	ld	a, b
	xor	a, -21 (ix)
	ld	b, a
	ld	a, e
	xor	a, -20 (ix)
	ld	e, a
	ld	a, d
	xor	a, -19 (ix)
	ld	d, a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-29 (ix), c
	ld	-28 (ix), b
	ld	-27 (ix), e
	ld	-30 (ix), #0x00
	ld	a, #0x04
00179$:
	sla	-29 (ix)
	rl	-28 (ix)
	rl	-27 (ix)
00180$:
	dec	a
	jr	NZ,00179$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00181$:
	srl	d
	rr	e
00182$:
	djnz	00181$
	ld	a, -30 (ix)
	or	a, e
	ld	-14 (ix), a
	ld	a, -29 (ix)
	or	a, d
	ld	-13 (ix), a
	ld	a, -28 (ix)
	or	a, l
	ld	-12 (ix), a
	ld	a, -27 (ix)
	or	a, h
	ld	-11 (ix), a
	ld	e, -60 (ix)
	ld	d, -59 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -26 (ix)
	add	a, -14 (ix)
	ld	-54 (ix), a
	ld	a, -25 (ix)
	adc	a, -13 (ix)
	ld	-53 (ix), a
	ld	a, -24 (ix)
	adc	a, -12 (ix)
	ld	-52 (ix), a
	ld	a, -23 (ix)
	adc	a, -11 (ix)
	ld	-51 (ix), a
	ld	e, -62 (ix)
	ld	d, -61 (ix)
	ld	hl, #0x0070
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	xor	a, -54 (ix)
	ld	e, a
	ld	a, -5 (ix)
	xor	a, -53 (ix)
	ld	d, a
	ld	a, -4 (ix)
	xor	a, -52 (ix)
	ld	c, a
	ld	a, -3 (ix)
	xor	a, -51 (ix)
	ld	b, a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-5 (ix), e
	ld	-4 (ix), d
	ld	-3 (ix), c
	ld	-6 (ix), #0x00
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	-50 (ix), a
	ld	a, -5 (ix)
	or	a, b
	ld	-49 (ix), a
	ld	a, -4 (ix)
	or	a, e
	ld	-48 (ix), a
	ld	a, -3 (ix)
	or	a, d
	ld	-47 (ix), a
	ld	e, -58 (ix)
	ld	d, -57 (ix)
	ld	hl, #0x0074
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -22 (ix)
	add	a, -50 (ix)
	ld	-6 (ix), a
	ld	a, -21 (ix)
	adc	a, -49 (ix)
	ld	-5 (ix), a
	ld	a, -20 (ix)
	adc	a, -48 (ix)
	ld	-4 (ix), a
	ld	a, -19 (ix)
	adc	a, -47 (ix)
	ld	-3 (ix), a
	ld	e, -56 (ix)
	ld	d, -55 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -14 (ix)
	xor	a, -6 (ix)
	ld	e, a
	ld	a, -13 (ix)
	xor	a, -5 (ix)
	ld	d, a
	ld	a, -12 (ix)
	xor	a, -4 (ix)
	ld	c, a
	ld	a, -11 (ix)
	xor	a, -3 (ix)
	ld	b, a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-14 (ix), e
	ld	-13 (ix), d
	ld	-12 (ix), c
	ld	-11 (ix), b
	ld	a, #0x07
00187$:
	sla	-14 (ix)
	rl	-13 (ix)
	rl	-12 (ix)
	rl	-11 (ix)
00188$:
	dec	a
	jr	NZ,00187$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, -14 (ix)
	or	a, c
	ld	-46 (ix), a
	ld	a, -13 (ix)
	or	a, b
	ld	-45 (ix), a
	ld	a, -12 (ix)
	or	a, e
	ld	-44 (ix), a
	ld	a, -11 (ix)
	or	a, d
	ld	-43 (ix), a
	ld	e, -60 (ix)
	ld	d, -59 (ix)
	ld	hl, #0x0078
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$26$3_0$38	= .
	.globl	C$chacha20.c$26$3_0$38
;/work/source_code/chacha20.c:26: QR(x[3], x[7], x[11], x[15]); // column 3
	ld	a, -102 (ix)
	add	a, #0x0c
	ld	-42 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-41 (ix), a
	ld	e, -42 (ix)
	ld	d, -41 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x1c
	ld	-40 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-39 (ix), a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -14 (ix)
	add	a, c
	ld	-30 (ix), a
	ld	a, -13 (ix)
	adc	a, b
	ld	-29 (ix), a
	ld	a, -12 (ix)
	adc	a, e
	ld	-28 (ix), a
	ld	a, -11 (ix)
	adc	a, d
	ld	-27 (ix), a
	ld	e, -42 (ix)
	ld	d, -41 (ix)
	ld	hl, #0x0088
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x3c
	ld	-38 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-37 (ix), a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	ld	a, e
	xor	a, -30 (ix)
	ld	e, a
	ld	a, d
	xor	a, -29 (ix)
	ld	d, a
	ld	a, c
	xor	a, -28 (ix)
	ld	c, a
	ld	a, b
	xor	a, -27 (ix)
	ld	b, a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-20 (ix), e
	ld	-19 (ix), d
	ld	-22 (ix), #0x00
	ld	-21 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -22 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -21 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -20 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -19 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -38 (ix)
	ld	d, -37 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -102 (ix)
	add	a, #0x2c
	ld	-36 (ix), a
	ld	a, -101 (ix)
	adc	a, #0x00
	ld	-35 (ix), a
	ld	l, -36 (ix)
	ld	h, -35 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -14 (ix)
	ld	-26 (ix), a
	ld	a, b
	adc	a, -13 (ix)
	ld	-25 (ix), a
	ld	a, e
	adc	a, -12 (ix)
	ld	-24 (ix), a
	ld	a, d
	adc	a, -11 (ix)
	ld	-23 (ix), a
	ld	e, -36 (ix)
	ld	d, -35 (ix)
	ld	hl, #0x008c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	xor	a, -26 (ix)
	ld	c, a
	ld	a, b
	xor	a, -25 (ix)
	ld	b, a
	ld	a, e
	xor	a, -24 (ix)
	ld	e, a
	ld	a, d
	xor	a, -23 (ix)
	ld	d, a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-33 (ix), c
	ld	-32 (ix), b
	ld	-31 (ix), e
	ld	-34 (ix), #0x00
	ld	a, #0x04
00195$:
	sla	-33 (ix)
	rl	-32 (ix)
	rl	-31 (ix)
00196$:
	dec	a
	jr	NZ,00195$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00197$:
	srl	d
	rr	e
00198$:
	djnz	00197$
	ld	a, -34 (ix)
	or	a, e
	ld	-22 (ix), a
	ld	a, -33 (ix)
	or	a, d
	ld	-21 (ix), a
	ld	a, -32 (ix)
	or	a, l
	ld	-20 (ix), a
	ld	a, -31 (ix)
	or	a, h
	ld	-19 (ix), a
	ld	e, -40 (ix)
	ld	d, -39 (ix)
	ld	hl, #0x0090
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -30 (ix)
	add	a, -22 (ix)
	ld	-34 (ix), a
	ld	a, -29 (ix)
	adc	a, -21 (ix)
	ld	-33 (ix), a
	ld	a, -28 (ix)
	adc	a, -20 (ix)
	ld	-32 (ix), a
	ld	a, -27 (ix)
	adc	a, -19 (ix)
	ld	-31 (ix), a
	ld	e, -42 (ix)
	ld	d, -41 (ix)
	ld	hl, #0x0084
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -14 (ix)
	xor	a, -34 (ix)
	ld	e, a
	ld	a, -13 (ix)
	xor	a, -33 (ix)
	ld	d, a
	ld	a, -12 (ix)
	xor	a, -32 (ix)
	ld	c, a
	ld	a, -11 (ix)
	xor	a, -31 (ix)
	ld	b, a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-29 (ix), e
	ld	-28 (ix), d
	ld	-27 (ix), c
	ld	-30 (ix), #0x00
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -30 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -29 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -28 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -27 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -38 (ix)
	ld	d, -37 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -26 (ix)
	add	a, -14 (ix)
	ld	-30 (ix), a
	ld	a, -25 (ix)
	adc	a, -13 (ix)
	ld	-29 (ix), a
	ld	a, -24 (ix)
	adc	a, -12 (ix)
	ld	-28 (ix), a
	ld	a, -23 (ix)
	adc	a, -11 (ix)
	ld	-27 (ix), a
	ld	e, -36 (ix)
	ld	d, -35 (ix)
	ld	hl, #0x0088
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -22 (ix)
	xor	a, -30 (ix)
	ld	e, a
	ld	a, -21 (ix)
	xor	a, -29 (ix)
	ld	d, a
	ld	a, -20 (ix)
	xor	a, -28 (ix)
	ld	c, a
	ld	a, -19 (ix)
	xor	a, -27 (ix)
	ld	b, a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-22 (ix), e
	ld	-21 (ix), d
	ld	-20 (ix), c
	ld	-19 (ix), b
	ld	a, #0x07
00203$:
	sla	-22 (ix)
	rl	-21 (ix)
	rl	-20 (ix)
	rl	-19 (ix)
00204$:
	dec	a
	jr	NZ,00203$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, -22 (ix)
	or	a, c
	ld	-26 (ix), a
	ld	a, -21 (ix)
	or	a, b
	ld	-25 (ix), a
	ld	a, -20 (ix)
	or	a, e
	ld	-24 (ix), a
	ld	a, -19 (ix)
	or	a, d
	ld	-23 (ix), a
	ld	e, -40 (ix)
	ld	d, -39 (ix)
	ld	hl, #0x008c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$28$3_0$38	= .
	.globl	C$chacha20.c$28$3_0$38
;/work/source_code/chacha20.c:28: QR(x[0], x[5], x[10], x[15]); // diagonal 1 (main diagonal)
	ld	a, -18 (ix)
	add	a, -10 (ix)
	ld	-22 (ix), a
	ld	a, -17 (ix)
	adc	a, -9 (ix)
	ld	-21 (ix), a
	ld	a, -16 (ix)
	adc	a, -8 (ix)
	ld	-20 (ix), a
	ld	a, -15 (ix)
	adc	a, -7 (ix)
	ld	-19 (ix), a
	ld	e, -102 (ix)
	ld	d, -101 (ix)
	ld	hl, #0x0090
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -14 (ix)
	xor	a, -22 (ix)
	ld	e, a
	ld	a, -13 (ix)
	xor	a, -21 (ix)
	ld	d, a
	ld	a, -12 (ix)
	xor	a, -20 (ix)
	ld	c, a
	ld	a, -11 (ix)
	xor	a, -19 (ix)
	ld	b, a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	ld	-14 (ix), #0x00
	ld	-13 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -14 (ix)
	or	a, c
	ld	-18 (ix), a
	ld	a, -13 (ix)
	or	a, b
	ld	-17 (ix), a
	ld	a, -12 (ix)
	or	a, e
	ld	-16 (ix), a
	ld	a, -11 (ix)
	or	a, d
	ld	-15 (ix), a
	ld	e, -38 (ix)
	ld	d, -37 (ix)
	ld	hl, #0x0094
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	add	a, -18 (ix)
	ld	-14 (ix), a
	ld	a, -5 (ix)
	adc	a, -17 (ix)
	ld	-13 (ix), a
	ld	a, -4 (ix)
	adc	a, -16 (ix)
	ld	-12 (ix), a
	ld	a, -3 (ix)
	adc	a, -15 (ix)
	ld	-11 (ix), a
	ld	e, -56 (ix)
	ld	d, -55 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -10 (ix)
	xor	a, -14 (ix)
	ld	c, a
	ld	a, -9 (ix)
	xor	a, -13 (ix)
	ld	b, a
	ld	a, -8 (ix)
	xor	a, -12 (ix)
	ld	e, a
	ld	a, -7 (ix)
	xor	a, -11 (ix)
	ld	d, a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-9 (ix), c
	ld	-8 (ix), b
	ld	-7 (ix), e
	ld	-10 (ix), #0x00
	ld	a, #0x04
00211$:
	sla	-9 (ix)
	rl	-8 (ix)
	rl	-7 (ix)
00212$:
	dec	a
	jr	NZ,00211$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00213$:
	srl	d
	rr	e
00214$:
	djnz	00213$
	ld	a, -10 (ix)
	or	a, e
	ld	-6 (ix), a
	ld	a, -9 (ix)
	or	a, d
	ld	-5 (ix), a
	ld	a, -8 (ix)
	or	a, l
	ld	-4 (ix), a
	ld	a, -7 (ix)
	or	a, h
	ld	-3 (ix), a
	ld	e, -80 (ix)
	ld	d, -79 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -22 (ix)
	add	a, -6 (ix)
	ld	c, a
	ld	a, -21 (ix)
	adc	a, -5 (ix)
	ld	b, a
	ld	a, -20 (ix)
	adc	a, -4 (ix)
	ld	e, a
	ld	a, -19 (ix)
	adc	a, -3 (ix)
	ld	d, a
	ld	l, -102 (ix)
	ld	h, -101 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, c
	xor	a, -18 (ix)
	ld	c, a
	ld	a, b
	xor	a, -17 (ix)
	ld	b, a
	ld	a, e
	xor	a, -16 (ix)
	ld	e, a
	ld	a, d
	xor	a, -15 (ix)
	ld	d, a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-9 (ix), c
	ld	-8 (ix), b
	ld	-7 (ix), e
	ld	-10 (ix), #0x00
	ld	c, d
	ld	b, #0x00
	ld	l, #0x00
	ld	h, #0x00
	ld	a, -10 (ix)
	or	a, c
	ld	e, a
	ld	a, -9 (ix)
	or	a, b
	ld	d, a
	ld	a, -8 (ix)
	or	a, l
	ld	c, a
	ld	a, -7 (ix)
	or	a, h
	ld	b, a
	ld	l, -38 (ix)
	ld	h, -37 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, -14 (ix)
	add	a, e
	ld	e, a
	ld	a, -13 (ix)
	adc	a, d
	ld	d, a
	ld	a, -12 (ix)
	adc	a, c
	ld	c, a
	ld	a, -11 (ix)
	adc	a, b
	ld	b, a
	ld	l, -56 (ix)
	ld	h, -55 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, e
	xor	a, -6 (ix)
	ld	e, a
	ld	a, d
	xor	a, -5 (ix)
	ld	d, a
	ld	a, c
	xor	a, -4 (ix)
	ld	c, a
	ld	a, b
	xor	a, -3 (ix)
	ld	b, a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00219$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00220$:
	dec	a
	jr	NZ,00219$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, c
	or	a, -6 (ix)
	ld	c, a
	ld	a, b
	or	a, -5 (ix)
	ld	b, a
	ld	a, e
	or	a, -4 (ix)
	ld	e, a
	ld	a, d
	or	a, -3 (ix)
	ld	d, a
	ld	l, -80 (ix)
	ld	h, -79 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$chacha20.c$29$3_0$38	= .
	.globl	C$chacha20.c$29$3_0$38
;/work/source_code/chacha20.c:29: QR(x[1], x[6], x[11], x[12]); // diagonal 2
	ld	a, -74 (ix)
	add	a, -46 (ix)
	ld	-6 (ix), a
	ld	a, -73 (ix)
	adc	a, -45 (ix)
	ld	-5 (ix), a
	ld	a, -72 (ix)
	adc	a, -44 (ix)
	ld	-4 (ix), a
	ld	a, -71 (ix)
	adc	a, -43 (ix)
	ld	-3 (ix), a
	ld	e, -82 (ix)
	ld	d, -81 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -94 (ix)
	xor	a, -6 (ix)
	ld	e, a
	ld	a, -93 (ix)
	xor	a, -5 (ix)
	ld	d, a
	ld	a, -92 (ix)
	xor	a, -4 (ix)
	ld	c, a
	ld	a, -91 (ix)
	xor	a, -3 (ix)
	ld	b, a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-8 (ix), e
	ld	-7 (ix), d
	ld	-10 (ix), #0x00
	ld	-9 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -10 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -9 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -8 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -7 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -98 (ix)
	ld	d, -97 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -30 (ix)
	add	a, -14 (ix)
	ld	-10 (ix), a
	ld	a, -29 (ix)
	adc	a, -13 (ix)
	ld	-9 (ix), a
	ld	a, -28 (ix)
	adc	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, -27 (ix)
	adc	a, -11 (ix)
	ld	-7 (ix), a
	ld	e, -36 (ix)
	ld	d, -35 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -46 (ix)
	xor	a, -10 (ix)
	ld	c, a
	ld	a, -45 (ix)
	xor	a, -9 (ix)
	ld	b, a
	ld	a, -44 (ix)
	xor	a, -8 (ix)
	ld	e, a
	ld	a, -43 (ix)
	xor	a, -7 (ix)
	ld	d, a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-21 (ix), c
	ld	-20 (ix), b
	ld	-19 (ix), e
	ld	-22 (ix), #0x00
	ld	a, #0x04
00227$:
	sla	-21 (ix)
	rl	-20 (ix)
	rl	-19 (ix)
00228$:
	dec	a
	jr	NZ,00227$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00229$:
	srl	d
	rr	e
00230$:
	djnz	00229$
	ld	a, -22 (ix)
	or	a, e
	ld	-18 (ix), a
	ld	a, -21 (ix)
	or	a, d
	ld	-17 (ix), a
	ld	a, -20 (ix)
	or	a, l
	ld	-16 (ix), a
	ld	a, -19 (ix)
	or	a, h
	ld	-15 (ix), a
	ld	e, -60 (ix)
	ld	d, -59 (ix)
	ld	hl, #0x0094
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	add	a, -18 (ix)
	ld	c, a
	ld	a, -5 (ix)
	adc	a, -17 (ix)
	ld	b, a
	ld	a, -4 (ix)
	adc	a, -16 (ix)
	ld	e, a
	ld	a, -3 (ix)
	adc	a, -15 (ix)
	ld	d, a
	ld	l, -82 (ix)
	ld	h, -81 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, c
	xor	a, -14 (ix)
	ld	c, a
	ld	a, b
	xor	a, -13 (ix)
	ld	b, a
	ld	a, e
	xor	a, -12 (ix)
	ld	e, a
	ld	a, d
	xor	a, -11 (ix)
	ld	d, a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-5 (ix), c
	ld	-4 (ix), b
	ld	-3 (ix), e
	ld	-6 (ix), #0x00
	ld	c, d
	ld	b, #0x00
	ld	l, #0x00
	ld	h, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	e, a
	ld	a, -5 (ix)
	or	a, b
	ld	d, a
	ld	a, -4 (ix)
	or	a, l
	ld	c, a
	ld	a, -3 (ix)
	or	a, h
	ld	b, a
	ld	l, -98 (ix)
	ld	h, -97 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, -10 (ix)
	add	a, e
	ld	e, a
	ld	a, -9 (ix)
	adc	a, d
	ld	d, a
	ld	a, -8 (ix)
	adc	a, c
	ld	c, a
	ld	a, -7 (ix)
	adc	a, b
	ld	b, a
	ld	l, -36 (ix)
	ld	h, -35 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, e
	xor	a, -18 (ix)
	ld	e, a
	ld	a, d
	xor	a, -17 (ix)
	ld	d, a
	ld	a, c
	xor	a, -16 (ix)
	ld	c, a
	ld	a, b
	xor	a, -15 (ix)
	ld	b, a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00235$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00236$:
	dec	a
	jr	NZ,00235$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, c
	or	a, -6 (ix)
	ld	c, a
	ld	a, b
	or	a, -5 (ix)
	ld	b, a
	ld	a, e
	or	a, -4 (ix)
	ld	e, a
	ld	a, d
	or	a, -3 (ix)
	ld	d, a
	ld	l, -60 (ix)
	ld	h, -59 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$chacha20.c$30$3_0$38	= .
	.globl	C$chacha20.c$30$3_0$38
;/work/source_code/chacha20.c:30: QR(x[2], x[7], x[ 8], x[13]); // diagonal 3
	ld	a, -54 (ix)
	add	a, -26 (ix)
	ld	-6 (ix), a
	ld	a, -53 (ix)
	adc	a, -25 (ix)
	ld	-5 (ix), a
	ld	a, -52 (ix)
	adc	a, -24 (ix)
	ld	-4 (ix), a
	ld	a, -51 (ix)
	adc	a, -23 (ix)
	ld	-3 (ix), a
	ld	e, -62 (ix)
	ld	d, -61 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -70 (ix)
	xor	a, -6 (ix)
	ld	e, a
	ld	a, -69 (ix)
	xor	a, -5 (ix)
	ld	d, a
	ld	a, -68 (ix)
	xor	a, -4 (ix)
	ld	c, a
	ld	a, -67 (ix)
	xor	a, -3 (ix)
	ld	b, a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-8 (ix), e
	ld	-7 (ix), d
	ld	-10 (ix), #0x00
	ld	-9 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -10 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -9 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -8 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -7 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -78 (ix)
	ld	d, -77 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -90 (ix)
	add	a, -14 (ix)
	ld	-10 (ix), a
	ld	a, -89 (ix)
	adc	a, -13 (ix)
	ld	-9 (ix), a
	ld	a, -88 (ix)
	adc	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, -87 (ix)
	adc	a, -11 (ix)
	ld	-7 (ix), a
	ld	e, -96 (ix)
	ld	d, -95 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -26 (ix)
	xor	a, -10 (ix)
	ld	c, a
	ld	a, -25 (ix)
	xor	a, -9 (ix)
	ld	b, a
	ld	a, -24 (ix)
	xor	a, -8 (ix)
	ld	e, a
	ld	a, -23 (ix)
	xor	a, -7 (ix)
	ld	d, a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-21 (ix), c
	ld	-20 (ix), b
	ld	-19 (ix), e
	ld	-22 (ix), #0x00
	ld	a, #0x04
00243$:
	sla	-21 (ix)
	rl	-20 (ix)
	rl	-19 (ix)
00244$:
	dec	a
	jr	NZ,00243$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00245$:
	srl	d
	rr	e
00246$:
	djnz	00245$
	ld	a, -22 (ix)
	or	a, e
	ld	-18 (ix), a
	ld	a, -21 (ix)
	or	a, d
	ld	-17 (ix), a
	ld	a, -20 (ix)
	or	a, l
	ld	-16 (ix), a
	ld	a, -19 (ix)
	or	a, h
	ld	-15 (ix), a
	ld	e, -40 (ix)
	ld	d, -39 (ix)
	ld	hl, #0x0094
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	add	a, -18 (ix)
	ld	c, a
	ld	a, -5 (ix)
	adc	a, -17 (ix)
	ld	b, a
	ld	a, -4 (ix)
	adc	a, -16 (ix)
	ld	e, a
	ld	a, -3 (ix)
	adc	a, -15 (ix)
	ld	d, a
	ld	l, -62 (ix)
	ld	h, -61 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, c
	xor	a, -14 (ix)
	ld	c, a
	ld	a, b
	xor	a, -13 (ix)
	ld	b, a
	ld	a, e
	xor	a, -12 (ix)
	ld	e, a
	ld	a, d
	xor	a, -11 (ix)
	ld	d, a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-5 (ix), c
	ld	-4 (ix), b
	ld	-3 (ix), e
	ld	-6 (ix), #0x00
	ld	c, d
	ld	b, #0x00
	ld	l, #0x00
	ld	h, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	e, a
	ld	a, -5 (ix)
	or	a, b
	ld	d, a
	ld	a, -4 (ix)
	or	a, l
	ld	c, a
	ld	a, -3 (ix)
	or	a, h
	ld	b, a
	ld	l, -78 (ix)
	ld	h, -77 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, -10 (ix)
	add	a, e
	ld	e, a
	ld	a, -9 (ix)
	adc	a, d
	ld	d, a
	ld	a, -8 (ix)
	adc	a, c
	ld	c, a
	ld	a, -7 (ix)
	adc	a, b
	ld	b, a
	ld	l, -96 (ix)
	ld	h, -95 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, e
	xor	a, -18 (ix)
	ld	e, a
	ld	a, d
	xor	a, -17 (ix)
	ld	d, a
	ld	a, c
	xor	a, -16 (ix)
	ld	c, a
	ld	a, b
	xor	a, -15 (ix)
	ld	b, a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00251$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00252$:
	dec	a
	jr	NZ,00251$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, c
	or	a, -6 (ix)
	ld	c, a
	ld	a, b
	or	a, -5 (ix)
	ld	b, a
	ld	a, e
	or	a, -4 (ix)
	ld	e, a
	ld	a, d
	or	a, -3 (ix)
	ld	d, a
	ld	l, -40 (ix)
	ld	h, -39 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$chacha20.c$31$3_0$38	= .
	.globl	C$chacha20.c$31$3_0$38
;/work/source_code/chacha20.c:31: QR(x[3], x[4], x[ 9], x[14]); // diagonal 4
	ld	a, -34 (ix)
	add	a, -86 (ix)
	ld	-6 (ix), a
	ld	a, -33 (ix)
	adc	a, -85 (ix)
	ld	-5 (ix), a
	ld	a, -32 (ix)
	adc	a, -84 (ix)
	ld	-4 (ix), a
	ld	a, -31 (ix)
	adc	a, -83 (ix)
	ld	-3 (ix), a
	ld	e, -42 (ix)
	ld	d, -41 (ix)
	ld	hl, #0x00a0
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -50 (ix)
	xor	a, -6 (ix)
	ld	e, a
	ld	a, -49 (ix)
	xor	a, -5 (ix)
	ld	d, a
	ld	a, -48 (ix)
	xor	a, -4 (ix)
	ld	c, a
	ld	a, -47 (ix)
	xor	a, -3 (ix)
	ld	b, a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-8 (ix), e
	ld	-7 (ix), d
	ld	-10 (ix), #0x00
	ld	-9 (ix), #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	a, -10 (ix)
	or	a, c
	ld	-14 (ix), a
	ld	a, -9 (ix)
	or	a, b
	ld	-13 (ix), a
	ld	a, -8 (ix)
	or	a, e
	ld	-12 (ix), a
	ld	a, -7 (ix)
	or	a, d
	ld	-11 (ix), a
	ld	e, -58 (ix)
	ld	d, -57 (ix)
	ld	hl, #0x0098
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -66 (ix)
	add	a, -14 (ix)
	ld	-10 (ix), a
	ld	a, -65 (ix)
	adc	a, -13 (ix)
	ld	-9 (ix), a
	ld	a, -64 (ix)
	adc	a, -12 (ix)
	ld	-8 (ix), a
	ld	a, -63 (ix)
	adc	a, -11 (ix)
	ld	-7 (ix), a
	ld	e, -76 (ix)
	ld	d, -75 (ix)
	ld	hl, #0x009c
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -86 (ix)
	xor	a, -10 (ix)
	ld	c, a
	ld	a, -85 (ix)
	xor	a, -9 (ix)
	ld	b, a
	ld	a, -84 (ix)
	xor	a, -8 (ix)
	ld	e, a
	ld	a, -83 (ix)
	xor	a, -7 (ix)
	ld	d, a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-21 (ix), c
	ld	-20 (ix), b
	ld	-19 (ix), e
	ld	-22 (ix), #0x00
	ld	a, #0x04
00259$:
	sla	-21 (ix)
	rl	-20 (ix)
	rl	-19 (ix)
00260$:
	dec	a
	jr	NZ,00259$
	ld	l, #0x00
	ld	h, #0x00
	ld	b, #0x04
00261$:
	srl	d
	rr	e
00262$:
	djnz	00261$
	ld	a, -22 (ix)
	or	a, e
	ld	-18 (ix), a
	ld	a, -21 (ix)
	or	a, d
	ld	-17 (ix), a
	ld	a, -20 (ix)
	or	a, l
	ld	-16 (ix), a
	ld	a, -19 (ix)
	or	a, h
	ld	-15 (ix), a
	ld	e, -100 (ix)
	ld	d, -99 (ix)
	ld	hl, #0x0094
	add	hl, sp
	ld	bc, #0x0004
	ldir
	ld	a, -6 (ix)
	add	a, -18 (ix)
	ld	c, a
	ld	a, -5 (ix)
	adc	a, -17 (ix)
	ld	b, a
	ld	a, -4 (ix)
	adc	a, -16 (ix)
	ld	e, a
	ld	a, -3 (ix)
	adc	a, -15 (ix)
	ld	d, a
	ld	l, -42 (ix)
	ld	h, -41 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, c
	xor	a, -14 (ix)
	ld	c, a
	ld	a, b
	xor	a, -13 (ix)
	ld	b, a
	ld	a, e
	xor	a, -12 (ix)
	ld	e, a
	ld	a, d
	xor	a, -11 (ix)
	ld	d, a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	-5 (ix), c
	ld	-4 (ix), b
	ld	-3 (ix), e
	ld	-6 (ix), #0x00
	ld	c, d
	ld	b, #0x00
	ld	l, #0x00
	ld	h, #0x00
	ld	a, -6 (ix)
	or	a, c
	ld	e, a
	ld	a, -5 (ix)
	or	a, b
	ld	d, a
	ld	a, -4 (ix)
	or	a, l
	ld	c, a
	ld	a, -3 (ix)
	or	a, h
	ld	b, a
	ld	l, -58 (ix)
	ld	h, -57 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, -10 (ix)
	add	a, e
	ld	e, a
	ld	a, -9 (ix)
	adc	a, d
	ld	d, a
	ld	a, -8 (ix)
	adc	a, c
	ld	c, a
	ld	a, -7 (ix)
	adc	a, b
	ld	b, a
	ld	l, -76 (ix)
	ld	h, -75 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	a, e
	xor	a, -18 (ix)
	ld	e, a
	ld	a, d
	xor	a, -17 (ix)
	ld	d, a
	ld	a, c
	xor	a, -16 (ix)
	ld	c, a
	ld	a, b
	xor	a, -15 (ix)
	ld	b, a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	inc	hl
	ld	(hl), c
	inc	hl
	ld	(hl), b
	ld	-6 (ix), e
	ld	-5 (ix), d
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	a, #0x07
00267$:
	sla	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
00268$:
	dec	a
	jr	NZ,00267$
	ld	c, b
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	srl	c
	ld	a, c
	or	a, -6 (ix)
	ld	c, a
	ld	a, b
	or	a, -5 (ix)
	ld	b, a
	ld	a, e
	or	a, -4 (ix)
	ld	e, a
	ld	a, d
	or	a, -3 (ix)
	ld	d, a
	ld	l, -100 (ix)
	ld	h, -99 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	dec	hl
	ld	-2 (ix), l
	ld	-1 (ix), h
	C$chacha20.c$21$3_0$38	= .
	.globl	C$chacha20.c$21$3_0$38
;/work/source_code/chacha20.c:21: for (i = 0; i < 10; i++) {
	ld	a, -1 (ix)
	or	a, -2 (ix)
	jp	NZ, 00108$
	C$chacha20.c$34$2_0$35	= .
	.globl	C$chacha20.c$34$2_0$35
;/work/source_code/chacha20.c:34: for (i = 0; i < 16; ++i)
	ld	bc, #0x0000
00109$:
	C$chacha20.c$35$2_0$39	= .
	.globl	C$chacha20.c$35$2_0$39
;/work/source_code/chacha20.c:35: out[i] = x[i] + in[i];
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, 4 (ix)
	add	a, e
	ld	-10 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-9 (ix), a
	ld	l, -102 (ix)
	ld	h, -101 (ix)
	add	hl, de
	push	de
	push	bc
	ld	e, l
	ld	d, h
	ld	hl, #0x00a2
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	bc
	pop	de
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	inc	hl
	ld	a, (hl)
	dec	hl
	ld	l, (hl)
	ld	h, a
	ld	a, -8 (ix)
	add	a, e
	ld	-4 (ix), a
	ld	a, -7 (ix)
	adc	a, d
	ld	-3 (ix), a
	ld	a, -6 (ix)
	adc	a, l
	ld	-2 (ix), a
	ld	a, -5 (ix)
	adc	a, h
	ld	-1 (ix), a
	push	bc
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	ld	hl, #0x00a4
	add	hl, sp
	ld	bc, #0x0004
	ldir
	pop	bc
	C$chacha20.c$34$2_0$39	= .
	.globl	C$chacha20.c$34$2_0$39
;/work/source_code/chacha20.c:34: for (i = 0; i < 16; ++i)
	inc	bc
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	C, 00109$
00111$:
	C$chacha20.c$36$2_0$35	= .
	.globl	C$chacha20.c$36$2_0$35
;/work/source_code/chacha20.c:36: }
	ld	sp, ix
	pop	ix
	C$chacha20.c$36$2_0$35	= .
	.globl	C$chacha20.c$36$2_0$35
	XG$chacha20_block$0$0	= .
	.globl	XG$chacha20_block$0$0
	ret
	G$chacha20_encrypt$0$0	= .
	.globl	G$chacha20_encrypt$0$0
	C$chacha20.c$38$2_0$41	= .
	.globl	C$chacha20.c$38$2_0$41
;/work/source_code/chacha20.c:38: void chacha20_encrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
;	---------------------------------
; Function chacha20_encrypt
; ---------------------------------
_chacha20_encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-209
	add	hl, sp
	ld	sp, hl
	C$chacha20.c$45$2_0$41	= .
	.globl	C$chacha20.c$45$2_0$41
;/work/source_code/chacha20.c:45: const char *constants = "expand 32-byte k";
	C$chacha20.c$48$1_0$41	= .
	.globl	C$chacha20.c$48$1_0$41
;/work/source_code/chacha20.c:48: state[0] = ((uint32_t*)constants)[0];
	ld	hl, #4
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	bc, (#___str_0 + 0)
	ld	de, (#___str_0 + 2)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$chacha20.c$49$1_0$41	= .
	.globl	C$chacha20.c$49$1_0$41
;/work/source_code/chacha20.c:49: state[1] = ((uint32_t*)constants)[1];
	ld	a, -2 (ix)
	add	a, #0x04
	ld	e, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	d, a
	push	de
	ld	de, #___str_0 + 4
	ld	hl, #0x00cd
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	de
	ld	hl, #0x00cb
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$50$1_0$41	= .
	.globl	C$chacha20.c$50$1_0$41
;/work/source_code/chacha20.c:50: state[2] = ((uint32_t*)constants)[2];
	ld	a, -2 (ix)
	add	a, #0x08
	ld	e, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	d, a
	push	de
	ld	de, #___str_0 + 8
	ld	hl, #0x00cd
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	de
	ld	hl, #0x00cb
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$51$1_0$41	= .
	.globl	C$chacha20.c$51$1_0$41
;/work/source_code/chacha20.c:51: state[3] = ((uint32_t*)constants)[3];
	ld	a, -2 (ix)
	add	a, #0x0c
	ld	e, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	d, a
	push	de
	ld	de, #___str_0 + 12
	ld	hl, #0x00cd
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	de
	ld	hl, #0x00cb
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$53$1_0$41	= .
	.globl	C$chacha20.c$53$1_0$41
;/work/source_code/chacha20.c:53: for(i=0; i<8; i++) state[4+i] = ((uint32_t*)key)[i];
	ld	bc, #0x0000
00108$:
	ld	a, c
	add	a, #0x04
	ld	l, a
	rla
	sbc	a, a
	ld	h, a
	add	hl, hl
	add	hl, hl
	ld	e, l
	ld	d, h
	ld	a, -2 (ix)
	add	a, e
	ld	-8 (ix), a
	ld	a, -1 (ix)
	adc	a, d
	ld	-7 (ix), a
	ld	e, 10 (ix)
	ld	d, 11 (ix)
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, hl
	add	hl, de
	ex	de, hl
	push	bc
	ld	hl, #0x00cd
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	bc
	push	bc
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	ld	hl, #0x00cd
	add	hl, sp
	ld	bc, #0x0004
	ldir
	pop	bc
	inc	bc
	ld	a, c
	sub	a, #0x08
	ld	a, b
	sbc	a, #0x00
	jp	C, 00108$
	C$chacha20.c$55$1_0$41	= .
	.globl	C$chacha20.c$55$1_0$41
;/work/source_code/chacha20.c:55: state[12] = counter;
	ld	a, -2 (ix)
	add	a, #0x30
	ld	-13 (ix), a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	-12 (ix), a
	ld	e, -13 (ix)
	ld	d, -12 (ix)
	ld	hl, #0x00df
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$chacha20.c$56$1_0$41	= .
	.globl	C$chacha20.c$56$1_0$41
;/work/source_code/chacha20.c:56: for(i=0; i<3; i++) state[13+i] = ((uint32_t*)nonce)[i];
	ld	bc, #0x0000
00110$:
	ld	a, c
	add	a, #0x0d
	ld	l, a
	rla
	sbc	a, a
	ld	h, a
	add	hl, hl
	add	hl, hl
	ld	e, l
	ld	d, h
	ld	a, -2 (ix)
	add	a, e
	ld	-8 (ix), a
	ld	a, -1 (ix)
	adc	a, d
	ld	-7 (ix), a
	ld	e, 12 (ix)
	ld	d, 13 (ix)
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, hl
	add	hl, de
	ex	de, hl
	push	bc
	ld	hl, #0x00cd
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	pop	bc
	push	bc
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	ld	hl, #0x00cd
	add	hl, sp
	ld	bc, #0x0004
	ldir
	pop	bc
	inc	bc
	ld	a, c
	sub	a, #0x03
	ld	a, b
	sbc	a, #0x00
	jp	C, 00110$
	C$chacha20.c$58$2_0$44	= .
	.globl	C$chacha20.c$58$2_0$44
;/work/source_code/chacha20.c:58: while (len > 0) {
	ld	a, -2 (ix)
	ld	-11 (ix), a
	ld	a, -1 (ix)
	ld	-10 (ix), a
	ld	hl, #68
	add	hl, sp
	ld	-9 (ix), l
	ld	-8 (ix), h
	ld	hl, #132
	add	hl, sp
	ld	-7 (ix), l
	ld	-6 (ix), h
00105$:
	ld	a, 9 (ix)
	or	a, 8 (ix)
	jp	Z, 00117$
	C$chacha20.c$59$2_0$44	= .
	.globl	C$chacha20.c$59$2_0$44
;/work/source_code/chacha20.c:59: chacha20_block(block, state);
	ld	e, -11 (ix)
	ld	d, -10 (ix)
	ld	c, -9 (ix)
	ld	b, -8 (ix)
	push	de
	push	bc
	call	_chacha20_block
	pop	af
	pop	af
	C$chacha20.c$60$2_0$44	= .
	.globl	C$chacha20.c$60$2_0$44
;/work/source_code/chacha20.c:60: state[12]++; // Increment counter
	ld	l, -13 (ix)
	ld	h, -12 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	c
	jp	NZ, 00179$
	inc	b
	jp	NZ, 00179$
	inc	de
00179$:
	ld	l, -13 (ix)
	ld	h, -12 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$chacha20.c$63$1_0$41	= .
	.globl	C$chacha20.c$63$1_0$41
;/work/source_code/chacha20.c:63: for (i = 0; i < 16; i++) {
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00112$:
	C$chacha20.c$64$4_0$46	= .
	.globl	C$chacha20.c$64$4_0$46
;/work/source_code/chacha20.c:64: uint32_t v = block[i];
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	add	hl, bc
	ld	e, l
	ld	d, h
	ld	hl, #0x0000
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	C$chacha20.c$65$4_0$46	= .
	.globl	C$chacha20.c$65$4_0$46
;/work/source_code/chacha20.c:65: block8[i*4+0] = (uint8_t)(v >> 0);
	ld	a, -2 (ix)
	add	a, a
	add	a, a
	ld	-3 (ix), a
	ld	a, -3 (ix)
	ld	c, a
	rla
	sbc	a, a
	ld	b, a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	add	hl, bc
	ld	iy, #0
	add	iy, sp
	ld	a, 0 (iy)
	ld	(hl), a
	C$chacha20.c$66$4_0$46	= .
	.globl	C$chacha20.c$66$4_0$46
;/work/source_code/chacha20.c:66: block8[i*4+1] = (uint8_t)(v >> 8);
	ld	a, -3 (ix)
	inc	a
	ld	c, a
	rla
	sbc	a, a
	ld	b, a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	add	hl, bc
	pop	bc
	push	bc
	ld	c, #0x00
	ld	(hl), b
	C$chacha20.c$67$4_0$46	= .
	.globl	C$chacha20.c$67$4_0$46
;/work/source_code/chacha20.c:67: block8[i*4+2] = (uint8_t)(v >> 16);
	ld	a, -3 (ix)
	inc	a
	inc	a
	ld	c, a
	rla
	sbc	a, a
	ld	b, a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	add	hl, bc
	ld	c, 2 (iy)
	ld	b, 3 (iy)
	ld	e, #0x00
	ld	d, #0x00
	ld	(hl), c
	C$chacha20.c$68$4_0$46	= .
	.globl	C$chacha20.c$68$4_0$46
;/work/source_code/chacha20.c:68: block8[i*4+3] = (uint8_t)(v >> 24);
	ld	a, -3 (ix)
	inc	a
	inc	a
	inc	a
	ld	c, a
	rla
	sbc	a, a
	ld	b, a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	add	hl, bc
	ld	c, 3 (iy)
	ld	b, #0x00
	ld	e, #0x00
	ld	d, #0x00
	ld	(hl), c
	C$chacha20.c$63$3_0$45	= .
	.globl	C$chacha20.c$63$3_0$45
;/work/source_code/chacha20.c:63: for (i = 0; i < 16; i++) {
	inc	-2 (ix)
	jp	NZ, 00186$
	inc	-1 (ix)
00186$:
	ld	a, -2 (ix)
	sub	a, #0x10
	ld	a, -1 (ix)
	sbc	a, #0x00
	jp	C, 00112$
	C$chacha20.c$71$2_1$47	= .
	.globl	C$chacha20.c$71$2_1$47
;/work/source_code/chacha20.c:71: size_t chunk = (len < 64) ? len : 64;
	ld	a, 8 (ix)
	sub	a, #0x40
	ld	a, 9 (ix)
	sbc	a, #0x00
	jp	NC, 00119$
	ld	a, 8 (ix)
	ld	-2 (ix), a
	ld	a, 9 (ix)
	ld	-1 (ix), a
	jp	00120$
00119$:
	ld	-2 (ix), #0x40
	xor	a, a
	ld	-1 (ix), a
00120$:
	ld	a, -2 (ix)
	ld	-5 (ix), a
	ld	a, -1 (ix)
	ld	-4 (ix), a
	C$chacha20.c$72$1_0$41	= .
	.globl	C$chacha20.c$72$1_0$41
;/work/source_code/chacha20.c:72: for (j = 0; j < chunk; j++) {
	ld	de, #0x0000
00115$:
	ld	a, e
	sub	a, -5 (ix)
	ld	a, d
	sbc	a, -4 (ix)
	jp	NC, 00104$
	C$chacha20.c$73$4_1$49	= .
	.globl	C$chacha20.c$73$4_1$49
;/work/source_code/chacha20.c:73: out[j] = in[j] ^ block8[j];
	ld	a, 4 (ix)
	add	a, e
	ld	-3 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-2 (ix), a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -7 (ix)
	ld	h, -6 (ix)
	add	hl, de
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	(hl), a
	C$chacha20.c$72$3_1$48	= .
	.globl	C$chacha20.c$72$3_1$48
;/work/source_code/chacha20.c:72: for (j = 0; j < chunk; j++) {
	inc	de
	jp	00115$
00104$:
	C$chacha20.c$76$2_1$47	= .
	.globl	C$chacha20.c$76$2_1$47
;/work/source_code/chacha20.c:76: len -= chunk;
	ld	a, 8 (ix)
	sub	a, -5 (ix)
	ld	8 (ix), a
	ld	a, 9 (ix)
	sbc	a, -4 (ix)
	ld	9 (ix), a
	C$chacha20.c$77$2_1$47	= .
	.globl	C$chacha20.c$77$2_1$47
;/work/source_code/chacha20.c:77: in += chunk;
	ld	a, 6 (ix)
	add	a, -5 (ix)
	ld	6 (ix), a
	ld	a, 7 (ix)
	adc	a, -4 (ix)
	ld	7 (ix), a
	C$chacha20.c$78$2_1$47	= .
	.globl	C$chacha20.c$78$2_1$47
;/work/source_code/chacha20.c:78: out += chunk;
	ld	a, 4 (ix)
	add	a, -5 (ix)
	ld	4 (ix), a
	ld	a, 5 (ix)
	adc	a, -4 (ix)
	ld	5 (ix), a
	jp	00105$
00117$:
	C$chacha20.c$80$1_0$41	= .
	.globl	C$chacha20.c$80$1_0$41
;/work/source_code/chacha20.c:80: }
	ld	sp, ix
	pop	ix
	C$chacha20.c$80$1_0$41	= .
	.globl	C$chacha20.c$80$1_0$41
	XG$chacha20_encrypt$0$0	= .
	.globl	XG$chacha20_encrypt$0$0
	ret
Fchacha20$__str_0$0_0$0 == .
___str_0:
	.ascii "expand 32-byte k"
	.db 0x00
	G$main$0$0	= .
	.globl	G$main$0$0
	C$chacha20.c$82$1_0$50	= .
	.globl	C$chacha20.c$82$1_0$50
;/work/source_code/chacha20.c:82: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-178
	add	hl, sp
	ld	sp, hl
	C$chacha20.c$83$2_0$50	= .
	.globl	C$chacha20.c$83$2_0$50
;/work/source_code/chacha20.c:83: uint8_t key[32] = {0};
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	xor	a, a
	ld	(de), a
	ld	c, e
	ld	b, d
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	c, e
	ld	b, d
	inc	bc
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	c, e
	ld	b, d
	inc	bc
	inc	bc
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0010
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0011
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0012
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0013
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0014
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0015
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0016
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0017
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0018
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x0019
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001a
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001b
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001c
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001d
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001e
	add	hl, de
	ld	(hl), #0x00
	ld	hl, #0x001f
	add	hl, de
	ld	(hl), #0x00
	C$chacha20.c$84$2_0$50	= .
	.globl	C$chacha20.c$84$2_0$50
;/work/source_code/chacha20.c:84: uint8_t nonce[12] = {0};
	ld	hl, #32
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), #0x00
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	inc	bc
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	inc	bc
	inc	bc
	inc	bc
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x04
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x05
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x06
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x07
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x08
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x09
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x0a
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	ld	a, -2 (ix)
	add	a, #0x0b
	ld	c, a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	C$chacha20.c$85$2_0$50	= .
	.globl	C$chacha20.c$85$2_0$50
;/work/source_code/chacha20.c:85: uint8_t data[64] = "Hello ChaCha20!";
	ld	hl, #44
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, #0x48
	ld	(bc), a
	ld	l, c
	ld	h, b
	inc	hl
	ld	(hl), #0x65
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), #0x6c
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0x6c
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x6f
	ld	hl, #0x0005
	add	hl, bc
	ld	(hl), #0x20
	ld	hl, #0x0006
	add	hl, bc
	ld	(hl), #0x43
	ld	hl, #0x0007
	add	hl, bc
	ld	(hl), #0x68
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0x61
	ld	hl, #0x0009
	add	hl, bc
	ld	(hl), #0x43
	ld	hl, #0x000a
	add	hl, bc
	ld	(hl), #0x68
	ld	hl, #0x000b
	add	hl, bc
	ld	(hl), #0x61
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0x32
	ld	hl, #0x000d
	add	hl, bc
	ld	(hl), #0x30
	ld	hl, #0x000e
	add	hl, bc
	ld	(hl), #0x21
	ld	hl, #0x000f
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0010
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0011
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0012
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0013
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0014
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0015
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0016
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0017
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0018
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0019
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001a
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001b
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001c
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001d
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001e
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x001f
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0020
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0021
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0022
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0023
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0024
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0025
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0026
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0027
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0028
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0029
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002a
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002b
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002c
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002d
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002e
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x002f
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0030
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0031
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0032
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0033
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0034
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0035
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0036
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0037
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0038
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x0039
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003a
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003b
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003c
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003d
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003e
	add	hl, bc
	ld	(hl), #0x00
	ld	hl, #0x003f
	add	hl, bc
	ld	(hl), #0x00
	C$chacha20.c$88$1_0$50	= .
	.globl	C$chacha20.c$88$1_0$50
;/work/source_code/chacha20.c:88: chacha20_encrypt(ciphertext, data, 64, key, nonce, 1);
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	-6 (ix), l
	ld	-5 (ix), h
	ld	-4 (ix), e
	ld	-3 (ix), d
	ld	hl, #108
	add	hl, sp
	ex	de, hl
	ld	-2 (ix), e
	ld	-1 (ix), d
	push	de
	ld	hl, #0x0000
	push	hl
	ld	hl, #0x0001
	push	hl
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	ld	hl, #0x0040
	push	hl
	push	bc
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	hl
	call	_chacha20_encrypt
	ld	hl, #14
	add	hl, sp
	ld	sp, hl
	pop	de
	C$chacha20.c$90$1_0$50	= .
	.globl	C$chacha20.c$90$1_0$50
;/work/source_code/chacha20.c:90: printf("ChaCha20 Test: %02x %02x\n", ciphertext[0], ciphertext[1]);
	ld	l, e
	ld	h, d
	inc	hl
	ld	c, (hl)
	ld	b, #0x00
	ld	a, (de)
	ld	e, a
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_2
	push	hl
	call	_printf
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	C$chacha20.c$91$1_0$50	= .
	.globl	C$chacha20.c$91$1_0$50
;/work/source_code/chacha20.c:91: return 0;
	ld	hl, #0x0000
00101$:
	C$chacha20.c$92$1_0$50	= .
	.globl	C$chacha20.c$92$1_0$50
;/work/source_code/chacha20.c:92: }
	ld	sp, ix
	pop	ix
	C$chacha20.c$92$1_0$50	= .
	.globl	C$chacha20.c$92$1_0$50
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Fchacha20$__str_2$0_0$0 == .
___str_2:
	.ascii "ChaCha20 Test: %02x %02x"
	.db 0x0a
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
