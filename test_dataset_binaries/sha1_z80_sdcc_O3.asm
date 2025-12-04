;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module sha1
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _strlen
	.globl _puts
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
	Fsha1$sha1_compress$0$0	= .
	.globl	Fsha1$sha1_compress$0$0
	C$sha1.c$21$0_0$35	= .
	.globl	C$sha1.c$21$0_0$35
;/work/source_code/testingfiles/sha1.c:21: static void sha1_compress(SHA1_ALT *ctx, const uint8_t block[64]) {
;	---------------------------------
; Function sha1_compress
; ---------------------------------
_sha1_compress:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-370
	add	hl, sp
	ld	sp, hl
	C$sha1.c$26$3_0$37	= .
	.globl	C$sha1.c$26$3_0$37
;/work/source_code/testingfiles/sha1.c:26: for (int i = 0; i < 16; i++) {
	ld	hl, #0
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	xor	a, a
	ld	-4 (ix), a
	ld	-3 (ix), a
00114$:
	ld	a, -4 (ix)
	sub	a, #0x10
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$sha1.c$27$3_0$37	= .
	.globl	C$sha1.c$27$3_0$37
;/work/source_code/testingfiles/sha1.c:27: w[i] = (block[4*i] << 24)
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, -2 (ix)
	add	a, e
	ld	-6 (ix), a
	ld	a, -1 (ix)
	adc	a, d
	ld	-5 (ix), a
	C$sha1.c$29$3_0$37	= .
	.globl	C$sha1.c$29$3_0$37
;/work/source_code/testingfiles/sha1.c:29: | (block[4*i+2] << 8)
	ld	c, e
	ld	b, d
	inc	bc
	inc	bc
	ld	a, 6 (ix)
	add	a, c
	ld	c, a
	ld	a, 7 (ix)
	adc	a, b
	ld	b, a
	ld	a, (bc)
	ld	b, a
	ld	c, #0x00
	C$sha1.c$30$3_0$37	= .
	.globl	C$sha1.c$30$3_0$37
;/work/source_code/testingfiles/sha1.c:30: | (block[4*i+3]);
	inc	de
	inc	de
	inc	de
	ld	a, 6 (ix)
	add	a, e
	ld	e, a
	ld	a, 7 (ix)
	adc	a, d
	ld	d, a
	ld	a, (de)
	ld	e, a
	ld	d, #0x00
	ld	a, c
	or	a, e
	ld	c, a
	ld	a, b
	or	a, d
	ld	b, a
	rla
	sbc	a, a
	ld	e, a
	ld	d, a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$sha1.c$26$2_0$36	= .
	.globl	C$sha1.c$26$2_0$36
;/work/source_code/testingfiles/sha1.c:26: for (int i = 0; i < 16; i++) {
	inc	-4 (ix)
	jr	NZ,00114$
	inc	-3 (ix)
	jr	00114$
00101$:
	C$sha1.c$34$2_0$38	= .
	.globl	C$sha1.c$34$2_0$38
;/work/source_code/testingfiles/sha1.c:34: for (int i = 16; i < 80; i++)
	ld	a, -2 (ix)
	ld	-16 (ix), a
	ld	a, -1 (ix)
	ld	-15 (ix), a
	ld	-4 (ix), #0x10
	xor	a, a
	ld	-3 (ix), a
00117$:
	ld	a, -4 (ix)
	sub	a, #0x50
	ld	a, -3 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00102$
	C$sha1.c$35$2_0$38	= .
	.globl	C$sha1.c$35$2_0$38
;/work/source_code/testingfiles/sha1.c:35: w[i] = ROL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
	ld	a, -4 (ix)
	ld	-6 (ix), a
	ld	a, -3 (ix)
	ld	-5 (ix), a
	ld	a, #0x02+1
	jr	00176$
00175$:
	sla	-6 (ix)
	rl	-5 (ix)
00176$:
	dec	a
	jr	NZ,00175$
	ld	a, -6 (ix)
	add	a, -16 (ix)
	ld	-14 (ix), a
	ld	a, -5 (ix)
	adc	a, -15 (ix)
	ld	-13 (ix), a
	ld	a, -4 (ix)
	add	a, #0xfd
	ld	c, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	b, a
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	add	hl, bc
	ex	de,hl
	ld	hl, #0x016a
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -4 (ix)
	add	a, #0xf8
	ld	c, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	b, a
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	add	hl, bc
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -8 (ix)
	xor	a, c
	ld	-12 (ix), a
	ld	a, -7 (ix)
	xor	a, b
	ld	-11 (ix), a
	ld	a, -6 (ix)
	xor	a, e
	ld	-10 (ix), a
	ld	a, -5 (ix)
	xor	a, d
	ld	-9 (ix), a
	ld	a, -4 (ix)
	add	a, #0xf2
	ld	c, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	b, a
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	add	hl, bc
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -12 (ix)
	xor	a, c
	ld	-8 (ix), a
	ld	a, -11 (ix)
	xor	a, b
	ld	-7 (ix), a
	ld	a, -10 (ix)
	xor	a, e
	ld	-6 (ix), a
	ld	a, -9 (ix)
	xor	a, d
	ld	-5 (ix), a
	ld	a, -4 (ix)
	add	a, #0xf0
	ld	c, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	b, a
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	add	hl, bc
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	inc	hl
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	ld	a, -8 (ix)
	xor	a, e
	ld	e, a
	ld	a, -7 (ix)
	xor	a, d
	ld	d, a
	ld	a, -6 (ix)
	xor	a, c
	ld	l, a
	ld	a, -5 (ix)
	xor	a, b
	ld	h, a
	ld	-8 (ix), e
	ld	-7 (ix), d
	ld	-6 (ix), l
	ld	-5 (ix), h
	sla	-8 (ix)
	rl	-7 (ix)
	rl	-6 (ix)
	rl	-5 (ix)
	ld	b, #0x1f
00187$:
	srl	h
	rr	l
	rr	d
	rr	e
	djnz	00187$
	ld	a, -8 (ix)
	or	a, e
	ld	c, a
	ld	a, -7 (ix)
	or	a, d
	ld	b, a
	ld	a, -6 (ix)
	or	a, l
	ld	e, a
	ld	a, -5 (ix)
	or	a, h
	ld	d, a
	ld	l, -14 (ix)
	ld	h, -13 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$sha1.c$34$2_0$38	= .
	.globl	C$sha1.c$34$2_0$38
;/work/source_code/testingfiles/sha1.c:34: for (int i = 16; i < 80; i++)
	inc	-4 (ix)
	jp	NZ,00117$
	inc	-3 (ix)
	jp	00117$
00102$:
	C$sha1.c$38$1_0$35	= .
	.globl	C$sha1.c$38$1_0$35
;/work/source_code/testingfiles/sha1.c:38: a = ctx->h[0];
	ld	a, 4 (ix)
	ld	-50 (ix), a
	ld	a, 5 (ix)
	ld	-49 (ix), a
	ld	e, -50 (ix)
	ld	d, -49 (ix)
	ld	hl, #0x0142
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	hl, #326
	add	hl, sp
	ex	de, hl
	ld	hl, #322
	add	hl, sp
	ld	bc, #4
	ldir
	C$sha1.c$39$1_0$35	= .
	.globl	C$sha1.c$39$1_0$35
;/work/source_code/testingfiles/sha1.c:39: b = ctx->h[1];
	ld	a, -50 (ix)
	add	a, #0x04
	ld	-40 (ix), a
	ld	a, -49 (ix)
	adc	a, #0x00
	ld	-39 (ix), a
	ld	e, -40 (ix)
	ld	d, -39 (ix)
	ld	hl, #0x014c
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	C$sha1.c$40$1_0$35	= .
	.globl	C$sha1.c$40$1_0$35
;/work/source_code/testingfiles/sha1.c:40: c = ctx->h[2];
	ld	a, -50 (ix)
	add	a, #0x08
	ld	-34 (ix), a
	ld	a, -49 (ix)
	adc	a, #0x00
	ld	-33 (ix), a
	ld	e, -34 (ix)
	ld	d, -33 (ix)
	ld	hl, #0x0152
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	C$sha1.c$41$1_0$35	= .
	.globl	C$sha1.c$41$1_0$35
;/work/source_code/testingfiles/sha1.c:41: d = ctx->h[3];
	ld	a, -50 (ix)
	add	a, #0x0c
	ld	-28 (ix), a
	ld	a, -49 (ix)
	adc	a, #0x00
	ld	-27 (ix), a
	ld	e, -28 (ix)
	ld	d, -27 (ix)
	ld	hl, #0x0158
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	C$sha1.c$42$1_0$35	= .
	.globl	C$sha1.c$42$1_0$35
;/work/source_code/testingfiles/sha1.c:42: e = ctx->h[4];
	ld	a, -50 (ix)
	add	a, #0x10
	ld	-22 (ix), a
	ld	a, -49 (ix)
	adc	a, #0x00
	ld	-21 (ix), a
	ld	e, -22 (ix)
	ld	d, -21 (ix)
	ld	hl, #0x015e
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	C$sha1.c$44$3_0$40	= .
	.globl	C$sha1.c$44$3_0$40
;/work/source_code/testingfiles/sha1.c:44: for (int i = 0; i < 80; i++) {
	ld	a, -2 (ix)
	ld	-16 (ix), a
	ld	a, -1 (ix)
	ld	-15 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00120$:
	ld	a, -2 (ix)
	sub	a, #0x50
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00112$
	C$sha1.c$47$3_0$40	= .
	.globl	C$sha1.c$47$3_0$40
;/work/source_code/testingfiles/sha1.c:47: if (i < 20) {
	ld	a, -2 (ix)
	sub	a, #0x14
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00110$
	C$sha1.c$48$4_0$41	= .
	.globl	C$sha1.c$48$4_0$41
;/work/source_code/testingfiles/sha1.c:48: f = (b & c) | ((~b) & d);
	ld	a, -38 (ix)
	and	a, -32 (ix)
	ld	c, a
	ld	a, -37 (ix)
	and	a, -31 (ix)
	ld	b, a
	ld	a, -36 (ix)
	and	a, -30 (ix)
	ld	e, a
	ld	a, -35 (ix)
	and	a, -29 (ix)
	ld	d, a
	ld	a, -38 (ix)
	cpl
	ld	-10 (ix), a
	ld	a, -37 (ix)
	cpl
	ld	-9 (ix), a
	ld	a, -36 (ix)
	cpl
	ld	-8 (ix), a
	ld	a, -35 (ix)
	cpl
	ld	-7 (ix), a
	ld	a, -10 (ix)
	and	a, -26 (ix)
	ld	-6 (ix), a
	ld	a, -9 (ix)
	and	a, -25 (ix)
	ld	-5 (ix), a
	ld	a, -8 (ix)
	and	a, -24 (ix)
	ld	-4 (ix), a
	ld	a, -7 (ix)
	and	a, -23 (ix)
	ld	-3 (ix), a
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
	ld	-14 (ix), c
	ld	-13 (ix), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	C$sha1.c$49$4_0$41	= .
	.globl	C$sha1.c$49$4_0$41
;/work/source_code/testingfiles/sha1.c:49: k = 0x5A827999;
	ld	-10 (ix), #0x99
	ld	-9 (ix), #0x79
	ld	-8 (ix), #0x82
	ld	-7 (ix), #0x5a
	jp	00111$
00110$:
	C$sha1.c$50$3_0$40	= .
	.globl	C$sha1.c$50$3_0$40
;/work/source_code/testingfiles/sha1.c:50: } else if (i < 40) {
	ld	a, -2 (ix)
	sub	a, #0x28
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00107$
	C$sha1.c$51$4_0$42	= .
	.globl	C$sha1.c$51$4_0$42
;/work/source_code/testingfiles/sha1.c:51: f = b ^ c ^ d;
	ld	a, -38 (ix)
	xor	a, -32 (ix)
	push	af
	ld	a, -37 (ix)
	xor	a, -31 (ix)
	ld	b, a
	ld	a, -36 (ix)
	xor	a, -30 (ix)
	ld	e, a
	ld	a, -35 (ix)
	xor	a, -29 (ix)
	ld	d, a
	pop	af
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
	ld	-14 (ix), c
	ld	-13 (ix), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	C$sha1.c$52$4_0$42	= .
	.globl	C$sha1.c$52$4_0$42
;/work/source_code/testingfiles/sha1.c:52: k = 0x6ED9EBA1;
	ld	-10 (ix), #0xa1
	ld	-9 (ix), #0xeb
	ld	-8 (ix), #0xd9
	ld	-7 (ix), #0x6e
	jp	00111$
00107$:
	C$sha1.c$53$3_0$40	= .
	.globl	C$sha1.c$53$3_0$40
;/work/source_code/testingfiles/sha1.c:53: } else if (i < 60) {
	ld	a, -2 (ix)
	sub	a, #0x3c
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00104$
	C$sha1.c$54$4_0$43	= .
	.globl	C$sha1.c$54$4_0$43
;/work/source_code/testingfiles/sha1.c:54: f = (b & c) | (b & d) | (c & d);
	ld	a, -38 (ix)
	and	a, -32 (ix)
	ld	-6 (ix), a
	ld	a, -37 (ix)
	and	a, -31 (ix)
	ld	-5 (ix), a
	ld	a, -36 (ix)
	and	a, -30 (ix)
	ld	-4 (ix), a
	ld	a, -35 (ix)
	and	a, -29 (ix)
	ld	-3 (ix), a
	ld	a, -38 (ix)
	and	a, -26 (ix)
	ld	c, a
	ld	a, -37 (ix)
	and	a, -25 (ix)
	ld	b, a
	ld	a, -36 (ix)
	and	a, -24 (ix)
	ld	e, a
	ld	a, -35 (ix)
	and	a, -23 (ix)
	push	af
	ld	a, -6 (ix)
	or	a, c
	ld	c, a
	ld	a, -5 (ix)
	or	a, b
	ld	b, a
	ld	a, -4 (ix)
	or	a, e
	ld	e, a
	pop	af
	or	a, -3 (ix)
	ld	d, a
	ld	a, -32 (ix)
	and	a, -26 (ix)
	ld	-6 (ix), a
	ld	a, -31 (ix)
	and	a, -25 (ix)
	ld	-5 (ix), a
	ld	a, -30 (ix)
	and	a, -24 (ix)
	ld	-4 (ix), a
	ld	a, -29 (ix)
	and	a, -23 (ix)
	ld	-3 (ix), a
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
	ld	-14 (ix), c
	ld	-13 (ix), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	C$sha1.c$55$4_0$43	= .
	.globl	C$sha1.c$55$4_0$43
;/work/source_code/testingfiles/sha1.c:55: k = 0x8F1BBCDC;
	ld	-10 (ix), #0xdc
	ld	-9 (ix), #0xbc
	ld	-8 (ix), #0x1b
	ld	-7 (ix), #0x8f
	jr	00111$
00104$:
	C$sha1.c$57$4_0$44	= .
	.globl	C$sha1.c$57$4_0$44
;/work/source_code/testingfiles/sha1.c:57: f = b ^ c ^ d;
	ld	a, -38 (ix)
	xor	a, -32 (ix)
	push	af
	ld	a, -37 (ix)
	xor	a, -31 (ix)
	ld	b, a
	ld	a, -36 (ix)
	xor	a, -30 (ix)
	ld	e, a
	ld	a, -35 (ix)
	xor	a, -29 (ix)
	ld	d, a
	pop	af
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
	ld	-14 (ix), c
	ld	-13 (ix), b
	ld	-12 (ix), e
	ld	-11 (ix), d
	C$sha1.c$58$4_0$44	= .
	.globl	C$sha1.c$58$4_0$44
;/work/source_code/testingfiles/sha1.c:58: k = 0xCA62C1D6;
	ld	-10 (ix), #0xd6
	ld	-9 (ix), #0xc1
	ld	-8 (ix), #0x62
	ld	-7 (ix), #0xca
00111$:
	C$sha1.c$61$3_0$40	= .
	.globl	C$sha1.c$61$3_0$40
;/work/source_code/testingfiles/sha1.c:61: temp = ROL32(a, 5) + f + e + k + w[i];
	ld	c, -44 (ix)
	ld	b, -43 (ix)
	ld	e, -42 (ix)
	ld	d, -41 (ix)
	ld	a, #0x05
00190$:
	sla	c
	rl	b
	rl	e
	rl	d
	dec	a
	jr	NZ,00190$
	ld	a, -41 (ix)
	ld	-6 (ix), a
	xor	a, a
	ld	-5 (ix), a
	ld	-4 (ix), a
	ld	-3 (ix), a
	ld	a, #0x03
00192$:
	srl	-6 (ix)
	dec	a
	jr	NZ, 00192$
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
	ld	a, c
	add	a, -14 (ix)
	ld	c, a
	ld	a, b
	adc	a, -13 (ix)
	ld	b, a
	ld	a, e
	adc	a, -12 (ix)
	ld	e, a
	ld	a, d
	adc	a, -11 (ix)
	ld	d, a
	ld	a, c
	add	a, -20 (ix)
	ld	c, a
	ld	a, b
	adc	a, -19 (ix)
	ld	b, a
	ld	a, e
	adc	a, -18 (ix)
	ld	e, a
	ld	a, d
	adc	a, -17 (ix)
	ld	d, a
	ld	a, c
	add	a, -10 (ix)
	ld	-6 (ix), a
	ld	a, b
	adc	a, -9 (ix)
	ld	-5 (ix), a
	ld	a, e
	adc	a, -8 (ix)
	ld	-4 (ix), a
	ld	a, d
	adc	a, -7 (ix)
	ld	-3 (ix), a
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, -16 (ix)
	ld	h, -15 (ix)
	add	hl, bc
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, -6 (ix)
	add	a, c
	ld	c, a
	ld	a, -5 (ix)
	adc	a, b
	ld	b, a
	ld	a, -4 (ix)
	adc	a, e
	ld	e, a
	ld	a, -3 (ix)
	adc	a, d
	ld	d, a
	ld	-6 (ix), c
	ld	-5 (ix), b
	ld	-4 (ix), e
	ld	-3 (ix), d
	C$sha1.c$62$3_0$40	= .
	.globl	C$sha1.c$62$3_0$40
;/work/source_code/testingfiles/sha1.c:62: e = d;
	ld	hl, #350
	add	hl, sp
	ex	de, hl
	ld	hl, #344
	add	hl, sp
	ld	bc, #4
	ldir
	C$sha1.c$63$3_0$40	= .
	.globl	C$sha1.c$63$3_0$40
;/work/source_code/testingfiles/sha1.c:63: d = c;
	ld	hl, #344
	add	hl, sp
	ex	de, hl
	ld	hl, #338
	add	hl, sp
	ld	bc, #4
	ldir
	C$sha1.c$64$3_0$40	= .
	.globl	C$sha1.c$64$3_0$40
;/work/source_code/testingfiles/sha1.c:64: c = ROL32(b, 30);
	ld	d, -38 (ix)
	ld	bc, #0x0000
	ld	e, #0x00
	ld	a, #0x06
00196$:
	sla	d
	dec	a
	jr	NZ,00196$
	ld	a, -38 (ix)
	ld	-10 (ix), a
	ld	a, -37 (ix)
	ld	-9 (ix), a
	ld	a, -36 (ix)
	ld	-8 (ix), a
	ld	a, -35 (ix)
	ld	-7 (ix), a
	ld	a, #0x02
00198$:
	srl	-7 (ix)
	rr	-8 (ix)
	rr	-9 (ix)
	rr	-10 (ix)
	dec	a
	jr	NZ, 00198$
	ld	a, c
	or	a, -10 (ix)
	ld	c, a
	ld	a, b
	or	a, -9 (ix)
	ld	b, a
	ld	a, e
	or	a, -8 (ix)
	ld	e, a
	ld	a, d
	or	a, -7 (ix)
	ld	d, a
	ld	-32 (ix), c
	ld	-31 (ix), b
	ld	-30 (ix), e
	ld	-29 (ix), d
	C$sha1.c$65$3_0$40	= .
	.globl	C$sha1.c$65$3_0$40
;/work/source_code/testingfiles/sha1.c:65: b = a;
	ld	hl, #332
	add	hl, sp
	ex	de, hl
	ld	hl, #326
	add	hl, sp
	ld	bc, #4
	ldir
	C$sha1.c$66$3_0$40	= .
	.globl	C$sha1.c$66$3_0$40
;/work/source_code/testingfiles/sha1.c:66: a = temp;
	ld	hl, #326
	add	hl, sp
	ex	de, hl
	ld	hl, #364
	add	hl, sp
	ld	bc, #4
	ldir
	C$sha1.c$44$2_0$39	= .
	.globl	C$sha1.c$44$2_0$39
;/work/source_code/testingfiles/sha1.c:44: for (int i = 0; i < 80; i++) {
	inc	-2 (ix)
	jp	NZ,00120$
	inc	-1 (ix)
	jp	00120$
00112$:
	C$sha1.c$69$1_0$35	= .
	.globl	C$sha1.c$69$1_0$35
;/work/source_code/testingfiles/sha1.c:69: ctx->h[0] += a;
	ld	a, -48 (ix)
	add	a, -44 (ix)
	ld	-4 (ix), a
	ld	a, -47 (ix)
	adc	a, -43 (ix)
	ld	-3 (ix), a
	ld	a, -46 (ix)
	adc	a, -42 (ix)
	ld	-2 (ix), a
	ld	a, -45 (ix)
	adc	a, -41 (ix)
	ld	-1 (ix), a
	ld	e, -50 (ix)
	ld	d, -49 (ix)
	ld	hl, #0x016e
	add	hl, sp
	ld	bc, #0x0004
	ldir
	C$sha1.c$70$1_0$35	= .
	.globl	C$sha1.c$70$1_0$35
;/work/source_code/testingfiles/sha1.c:70: ctx->h[1] += b;
	ld	e, -40 (ix)
	ld	d, -39 (ix)
	ld	hl, #0x016e
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0004
	ldir
	ld	a, -4 (ix)
	add	a, -38 (ix)
	ld	c, a
	ld	a, -3 (ix)
	adc	a, -37 (ix)
	ld	b, a
	ld	a, -2 (ix)
	adc	a, -36 (ix)
	ld	e, a
	ld	a, -1 (ix)
	adc	a, -35 (ix)
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
	C$sha1.c$71$1_0$35	= .
	.globl	C$sha1.c$71$1_0$35
;/work/source_code/testingfiles/sha1.c:71: ctx->h[2] += c;
	ld	l, -34 (ix)
	ld	h, -33 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -32 (ix)
	ld	c, a
	ld	a, b
	adc	a, -31 (ix)
	ld	b, a
	ld	a, e
	adc	a, -30 (ix)
	ld	e, a
	ld	a, d
	adc	a, -29 (ix)
	ld	d, a
	ld	l, -34 (ix)
	ld	h, -33 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$sha1.c$72$1_0$35	= .
	.globl	C$sha1.c$72$1_0$35
;/work/source_code/testingfiles/sha1.c:72: ctx->h[3] += d;
	ld	l, -28 (ix)
	ld	h, -27 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -26 (ix)
	ld	c, a
	ld	a, b
	adc	a, -25 (ix)
	ld	b, a
	ld	a, e
	adc	a, -24 (ix)
	ld	e, a
	ld	a, d
	adc	a, -23 (ix)
	ld	d, a
	ld	l, -28 (ix)
	ld	h, -27 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$sha1.c$73$1_0$35	= .
	.globl	C$sha1.c$73$1_0$35
;/work/source_code/testingfiles/sha1.c:73: ctx->h[4] += e;
	ld	l, -22 (ix)
	ld	h, -21 (ix)
	ld	c, (hl)
	inc	hl
	ld	b, (hl)
	inc	hl
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	ld	a, c
	add	a, -20 (ix)
	ld	c, a
	ld	a, b
	adc	a, -19 (ix)
	ld	b, a
	ld	a, e
	adc	a, -18 (ix)
	ld	e, a
	ld	a, d
	adc	a, -17 (ix)
	ld	d, a
	ld	l, -22 (ix)
	ld	h, -21 (ix)
	ld	(hl), c
	inc	hl
	ld	(hl), b
	inc	hl
	ld	(hl), e
	inc	hl
	ld	(hl), d
	C$sha1.c$74$1_0$35	= .
	.globl	C$sha1.c$74$1_0$35
;/work/source_code/testingfiles/sha1.c:74: }
	ld	sp, ix
	pop	ix
	C$sha1.c$74$1_0$35	= .
	.globl	C$sha1.c$74$1_0$35
	XFsha1$sha1_compress$0$0	= .
	.globl	XFsha1$sha1_compress$0$0
	ret
	Fsha1$sha1_init_alt$0$0	= .
	.globl	Fsha1$sha1_init_alt$0$0
	C$sha1.c$78$1_0$46	= .
	.globl	C$sha1.c$78$1_0$46
;/work/source_code/testingfiles/sha1.c:78: static void sha1_init_alt(SHA1_ALT *ctx) {
;	---------------------------------
; Function sha1_init_alt
; ---------------------------------
_sha1_init_alt:
	C$sha1.c$79$1_0$46	= .
	.globl	C$sha1.c$79$1_0$46
;/work/source_code/testingfiles/sha1.c:79: ctx->h[0] = 0x67452301;
	pop	de
	pop	bc
	push	bc
	push	de
	ld	l, c
	ld	h, b
	ld	(hl), #0x01
	inc	hl
	ld	(hl), #0x23
	inc	hl
	ld	(hl), #0x45
	inc	hl
	ld	(hl), #0x67
	C$sha1.c$80$1_0$46	= .
	.globl	C$sha1.c$80$1_0$46
;/work/source_code/testingfiles/sha1.c:80: ctx->h[1] = 0xEFCDAB89;
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x89
	inc	hl
	ld	(hl), #0xab
	inc	hl
	ld	(hl), #0xcd
	inc	hl
	ld	(hl), #0xef
	C$sha1.c$81$1_0$46	= .
	.globl	C$sha1.c$81$1_0$46
;/work/source_code/testingfiles/sha1.c:81: ctx->h[2] = 0x98BADCFE;
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0xfe
	inc	hl
	ld	(hl), #0xdc
	inc	hl
	ld	(hl), #0xba
	inc	hl
	ld	(hl), #0x98
	C$sha1.c$82$1_0$46	= .
	.globl	C$sha1.c$82$1_0$46
;/work/source_code/testingfiles/sha1.c:82: ctx->h[3] = 0x10325476;
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0x76
	inc	hl
	ld	(hl), #0x54
	inc	hl
	ld	(hl), #0x32
	inc	hl
	ld	(hl), #0x10
	C$sha1.c$83$1_0$46	= .
	.globl	C$sha1.c$83$1_0$46
;/work/source_code/testingfiles/sha1.c:83: ctx->h[4] = 0xC3D2E1F0;
	ld	hl, #0x0010
	add	hl, bc
	ld	(hl), #0xf0
	inc	hl
	ld	(hl), #0xe1
	inc	hl
	ld	(hl), #0xd2
	inc	hl
	ld	(hl), #0xc3
	C$sha1.c$85$1_0$46	= .
	.globl	C$sha1.c$85$1_0$46
;/work/source_code/testingfiles/sha1.c:85: ctx->bitcount = 0;
	ld	hl, #0x0014
	add	hl, bc
	xor	a, a
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	inc	hl
	ld	(hl), a
	C$sha1.c$86$1_0$46	= .
	.globl	C$sha1.c$86$1_0$46
;/work/source_code/testingfiles/sha1.c:86: ctx->buffer_len = 0;
	ld	hl, #0x005c
	add	hl, bc
	xor	a, a
	ld	(hl), a
	inc	hl
	ld	(hl), a
	C$sha1.c$87$1_0$46	= .
	.globl	C$sha1.c$87$1_0$46
;/work/source_code/testingfiles/sha1.c:87: }
	C$sha1.c$87$1_0$46	= .
	.globl	C$sha1.c$87$1_0$46
	XFsha1$sha1_init_alt$0$0	= .
	.globl	XFsha1$sha1_init_alt$0$0
	ret
	Fsha1$sha1_update_alt$0$0	= .
	.globl	Fsha1$sha1_update_alt$0$0
	C$sha1.c$91$1_0$48	= .
	.globl	C$sha1.c$91$1_0$48
;/work/source_code/testingfiles/sha1.c:91: static void sha1_update_alt(SHA1_ALT *ctx, const uint8_t *data, size_t len) {
;	---------------------------------
; Function sha1_update_alt
; ---------------------------------
_sha1_update_alt:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-17
	add	hl, sp
	ld	sp, hl
	C$sha1.c$92$1_0$48	= .
	.globl	C$sha1.c$92$1_0$48
;/work/source_code/testingfiles/sha1.c:92: ctx->bitcount += (uint64_t)len * 8;
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	ld	hl, #0x0014
	add	hl, bc
	ex	de, hl
	push	de
	push	bc
	ld	hl, #0x0004
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0008
	ldir
	pop	bc
	pop	de
	ld	a, 8 (ix)
	ld	-8 (ix), a
	ld	a, 9 (ix)
	ld	-7 (ix), a
	xor	a, a
	ld	-6 (ix), a
	ld	-5 (ix), a
	ld	-4 (ix), a
	ld	-3 (ix), a
	ld	-2 (ix), a
	ld	-1 (ix), a
	ld	a, #0x03
00130$:
	sla	-8 (ix)
	rl	-7 (ix)
	rl	-6 (ix)
	rl	-5 (ix)
	rl	-4 (ix)
	rl	-3 (ix)
	rl	-2 (ix)
	rl	-1 (ix)
	dec	a
	jr	NZ,00130$
	ld	a, -17 (ix)
	add	a, -8 (ix)
	ld	-8 (ix), a
	ld	a, -16 (ix)
	adc	a, -7 (ix)
	ld	-7 (ix), a
	ld	a, -15 (ix)
	adc	a, -6 (ix)
	ld	-6 (ix), a
	ld	a, -14 (ix)
	adc	a, -5 (ix)
	ld	-5 (ix), a
	ld	a, -13 (ix)
	adc	a, -4 (ix)
	ld	-4 (ix), a
	ld	a, -12 (ix)
	adc	a, -3 (ix)
	ld	-3 (ix), a
	ld	a, -11 (ix)
	adc	a, -2 (ix)
	ld	-2 (ix), a
	ld	a, -10 (ix)
	adc	a, -1 (ix)
	ld	-1 (ix), a
	push	bc
	ld	hl, #0x000b
	add	hl, sp
	ld	bc, #0x0008
	ldir
	pop	bc
	C$sha1.c$94$2_0$49	= .
	.globl	C$sha1.c$94$2_0$49
;/work/source_code/testingfiles/sha1.c:94: while (len > 0) {
	ld	hl, #0x001c
	add	hl, bc
	ld	-8 (ix), l
	ld	-7 (ix), h
	ld	-6 (ix), c
	ld	-5 (ix), b
00103$:
	ld	a, 9 (ix)
	or	a, 8 (ix)
	jp	Z, 00106$
	C$sha1.c$95$2_0$49	= .
	.globl	C$sha1.c$95$2_0$49
;/work/source_code/testingfiles/sha1.c:95: size_t space = SHA1_BLOCK - ctx->buffer_len;
	ld	hl, #0x005c
	add	hl, bc
	ld	-4 (ix), l
	ld	-3 (ix), h
	ld	a, (hl)
	inc	hl
	ld	h, (hl)
	ld	l, a
	ld	a, #0x40
	sub	a, l
	ld	e, a
	ld	a, #0x00
	sbc	a, h
	ld	d, a
	C$sha1.c$96$2_0$49	= .
	.globl	C$sha1.c$96$2_0$49
;/work/source_code/testingfiles/sha1.c:96: size_t copy_len = (len < space) ? len : space;
	ld	a, 8 (ix)
	sub	a, e
	ld	a, 9 (ix)
	sbc	a, d
	jr	NC,00108$
	ld	e, 8 (ix)
	ld	d, 9 (ix)
00108$:
	C$sha1.c$98$2_0$49	= .
	.globl	C$sha1.c$98$2_0$49
;/work/source_code/testingfiles/sha1.c:98: memcpy(ctx->buffer + ctx->buffer_len, data, copy_len);
	ld	a, l
	add	a, -8 (ix)
	ld	l, a
	ld	a, h
	adc	a, -7 (ix)
	ld	h, a
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	push	bc
	push	de
	push	de
	push	hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	hl
	call	___memcpy
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	pop	de
	pop	bc
	C$sha1.c$99$2_0$49	= .
	.globl	C$sha1.c$99$2_0$49
;/work/source_code/testingfiles/sha1.c:99: ctx->buffer_len += copy_len;
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, (hl)
	inc	hl
	ld	h, (hl)
	ld	l, a
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -2 (ix)
	ld	(hl), a
	inc	hl
	ld	a, -1 (ix)
	ld	(hl), a
	C$sha1.c$100$2_0$49	= .
	.globl	C$sha1.c$100$2_0$49
;/work/source_code/testingfiles/sha1.c:100: data += copy_len;
	ld	a, 6 (ix)
	add	a, e
	ld	6 (ix), a
	ld	a, 7 (ix)
	adc	a, d
	ld	7 (ix), a
	C$sha1.c$101$2_0$49	= .
	.globl	C$sha1.c$101$2_0$49
;/work/source_code/testingfiles/sha1.c:101: len -= copy_len;
	ld	a, 8 (ix)
	sub	a, e
	ld	8 (ix), a
	ld	a, 9 (ix)
	sbc	a, d
	ld	9 (ix), a
	C$sha1.c$103$2_0$49	= .
	.globl	C$sha1.c$103$2_0$49
;/work/source_code/testingfiles/sha1.c:103: if (ctx->buffer_len == 64) {
	ld	a, -2 (ix)
	sub	a, #0x40
	or	a, -1 (ix)
	jp	NZ,00103$
	C$sha1.c$104$3_0$50	= .
	.globl	C$sha1.c$104$3_0$50
;/work/source_code/testingfiles/sha1.c:104: sha1_compress(ctx, ctx->buffer);
	ld	hl, #0x001c
	add	hl, bc
	push	bc
	push	hl
	push	bc
	call	_sha1_compress
	pop	af
	pop	af
	pop	bc
	C$sha1.c$105$3_0$50	= .
	.globl	C$sha1.c$105$3_0$50
;/work/source_code/testingfiles/sha1.c:105: ctx->buffer_len = 0;
	ld	a, -6 (ix)
	add	a, #0x5c
	ld	e, a
	ld	a, -5 (ix)
	adc	a, #0x00
	ld	d, a
	xor	a, a
	ld	(de), a
	inc	de
	ld	(de), a
	jp	00103$
00106$:
	C$sha1.c$108$1_0$48	= .
	.globl	C$sha1.c$108$1_0$48
;/work/source_code/testingfiles/sha1.c:108: }
	ld	sp, ix
	pop	ix
	C$sha1.c$108$1_0$48	= .
	.globl	C$sha1.c$108$1_0$48
	XFsha1$sha1_update_alt$0$0	= .
	.globl	XFsha1$sha1_update_alt$0$0
	ret
	Fsha1$sha1_final_alt$0$0	= .
	.globl	Fsha1$sha1_final_alt$0$0
	C$sha1.c$112$1_0$52	= .
	.globl	C$sha1.c$112$1_0$52
;/work/source_code/testingfiles/sha1.c:112: static void sha1_final_alt(SHA1_ALT *ctx, uint8_t out[20]) {
;	---------------------------------
; Function sha1_final_alt
; ---------------------------------
_sha1_final_alt:
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-24
	add	hl, sp
	ld	sp, hl
	C$sha1.c$114$2_1$52	= .
	.globl	C$sha1.c$114$2_1$52
;/work/source_code/testingfiles/sha1.c:114: ctx->buffer[ctx->buffer_len++] = 0x80;
	ld	a, 4 (ix)
	ld	-8 (ix), a
	ld	a, 5 (ix)
	ld	-7 (ix), a
	ld	a, -8 (ix)
	ld	-6 (ix), a
	ld	a, -7 (ix)
	ld	-5 (ix), a
	ld	a, -8 (ix)
	add	a, #0x1c
	ld	c, a
	ld	a, -7 (ix)
	adc	a, #0x00
	ld	b, a
	ld	a, -8 (ix)
	add	a, #0x5c
	ld	-4 (ix), a
	ld	a, -7 (ix)
	adc	a, #0x00
	ld	-3 (ix), a
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, (hl)
	ld	-2 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-1 (ix), a
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	inc	de
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	add	hl, bc
	ld	(hl), #0x80
	C$sha1.c$117$1_0$52	= .
	.globl	C$sha1.c$117$1_0$52
;/work/source_code/testingfiles/sha1.c:117: if (ctx->buffer_len > 56) {
	ld	a, #0x38
	cp	a, e
	ld	a, #0x00
	sbc	a, d
	jr	NC,00122$
	C$sha1.c$118$2_0$53	= .
	.globl	C$sha1.c$118$2_0$53
;/work/source_code/testingfiles/sha1.c:118: while (ctx->buffer_len < 64)
00101$:
	C$sha1.c$114$2_1$52	= .
	.globl	C$sha1.c$114$2_1$52
;/work/source_code/testingfiles/sha1.c:114: ctx->buffer[ctx->buffer_len++] = 0x80;
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	e, (hl)
	inc	hl
	ld	d, (hl)
	C$sha1.c$118$2_0$53	= .
	.globl	C$sha1.c$118$2_0$53
;/work/source_code/testingfiles/sha1.c:118: while (ctx->buffer_len < 64)
	ld	a, e
	sub	a, #0x40
	ld	a, d
	sbc	a, #0x00
	jr	NC,00103$
	C$sha1.c$119$2_0$53	= .
	.globl	C$sha1.c$119$2_0$53
;/work/source_code/testingfiles/sha1.c:119: ctx->buffer[ctx->buffer_len++] = 0x00;
	ld	hl, #0x0001
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	a, -2 (ix)
	ld	(hl), a
	inc	hl
	ld	a, -1 (ix)
	ld	(hl), a
	ld	l, c
	ld	h, b
	add	hl, de
	ld	(hl), #0x00
	jr	00101$
00103$:
	C$sha1.c$120$2_0$53	= .
	.globl	C$sha1.c$120$2_0$53
;/work/source_code/testingfiles/sha1.c:120: sha1_compress(ctx, ctx->buffer);
	ld	a, -6 (ix)
	add	a, #0x1c
	ld	c, a
	ld	a, -5 (ix)
	adc	a, #0x00
	ld	b, a
	push	bc
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	call	_sha1_compress
	pop	af
	pop	af
	C$sha1.c$114$2_1$52	= .
	.globl	C$sha1.c$114$2_1$52
;/work/source_code/testingfiles/sha1.c:114: ctx->buffer[ctx->buffer_len++] = 0x80;
	ld	a, 4 (ix)
	ld	-8 (ix), a
	ld	a, 5 (ix)
	ld	-7 (ix), a
	C$sha1.c$121$2_0$53	= .
	.globl	C$sha1.c$121$2_0$53
;/work/source_code/testingfiles/sha1.c:121: ctx->buffer_len = 0;
	ld	a, -8 (ix)
	add	a, #0x5c
	ld	c, a
	ld	a, -7 (ix)
	adc	a, #0x00
	ld	b, a
	xor	a, a
	ld	(bc), a
	inc	bc
	ld	(bc), a
	C$sha1.c$125$2_1$52	= .
	.globl	C$sha1.c$125$2_1$52
;/work/source_code/testingfiles/sha1.c:125: while (ctx->buffer_len < 56)
00122$:
	ld	c, -8 (ix)
	ld	b, -7 (ix)
00106$:
	ld	hl, #0x005c
	add	hl, bc
	ld	-8 (ix), l
	ld	-7 (ix), h
	ld	a, (hl)
	ld	-4 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-3 (ix), a
	C$sha1.c$126$2_1$52	= .
	.globl	C$sha1.c$126$2_1$52
;/work/source_code/testingfiles/sha1.c:126: ctx->buffer[ctx->buffer_len++] = 0x00;
	ld	hl, #0x001c
	add	hl, bc
	ld	-2 (ix), l
	ld	-1 (ix), h
	C$sha1.c$125$1_0$52	= .
	.globl	C$sha1.c$125$1_0$52
;/work/source_code/testingfiles/sha1.c:125: while (ctx->buffer_len < 56)
	ld	a, -4 (ix)
	sub	a, #0x38
	ld	a, -3 (ix)
	sbc	a, #0x00
	jr	NC,00108$
	C$sha1.c$126$1_0$52	= .
	.globl	C$sha1.c$126$1_0$52
;/work/source_code/testingfiles/sha1.c:126: ctx->buffer[ctx->buffer_len++] = 0x00;
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), e
	inc	hl
	ld	(hl), d
	ld	a, -2 (ix)
	add	a, -4 (ix)
	ld	e, a
	ld	a, -1 (ix)
	adc	a, -3 (ix)
	ld	d, a
	xor	a, a
	ld	(de), a
	jr	00106$
00108$:
	C$sha1.c$129$1_1$54	= .
	.globl	C$sha1.c$129$1_1$54
;/work/source_code/testingfiles/sha1.c:129: uint64_t bc = ctx->bitcount;
	ld	l, c
	ld	h, b
	ld	de, #0x0014
	add	hl, de
	ld	a, (hl)
	ld	-16 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-15 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-14 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-13 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-12 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-11 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-10 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-9 (ix), a
	C$sha1.c$130$3_1$56	= .
	.globl	C$sha1.c$130$3_1$56
;/work/source_code/testingfiles/sha1.c:130: for (int i = 7; i >= 0; i--) {
	ld	a, -2 (ix)
	ld	-6 (ix), a
	ld	a, -1 (ix)
	ld	-5 (ix), a
	ld	de, #0x0007
00112$:
	bit	7, d
	jp	NZ, 00109$
	C$sha1.c$131$3_1$56	= .
	.globl	C$sha1.c$131$3_1$56
;/work/source_code/testingfiles/sha1.c:131: ctx->buffer[ctx->buffer_len++] = (uint8_t)(bc >> (i * 8));
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, (hl)
	ld	-4 (ix), a
	inc	hl
	ld	a, (hl)
	ld	-3 (ix), a
	ld	a, -4 (ix)
	add	a, #0x01
	ld	-2 (ix), a
	ld	a, -3 (ix)
	adc	a, #0x00
	ld	-1 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, -2 (ix)
	ld	(hl), a
	inc	hl
	ld	a, -1 (ix)
	ld	(hl), a
	ld	a, -4 (ix)
	add	a, -6 (ix)
	ld	l, a
	ld	a, -3 (ix)
	adc	a, -5 (ix)
	ld	h, a
	ld	a, e
	add	a, a
	add	a, a
	add	a, a
	push	af
	ld	a, -16 (ix)
	ld	-24 (ix), a
	ld	a, -15 (ix)
	ld	-23 (ix), a
	ld	a, -14 (ix)
	ld	-22 (ix), a
	ld	a, -13 (ix)
	ld	-21 (ix), a
	ld	a, -12 (ix)
	ld	-20 (ix), a
	ld	a, -11 (ix)
	ld	-19 (ix), a
	ld	a, -10 (ix)
	ld	-18 (ix), a
	ld	a, -9 (ix)
	ld	-17 (ix), a
	pop	af
	inc	a
	jr	00162$
00161$:
	srl	-17 (ix)
	rr	-18 (ix)
	rr	-19 (ix)
	rr	-20 (ix)
	rr	-21 (ix)
	rr	-22 (ix)
	rr	-23 (ix)
	rr	-24 (ix)
00162$:
	dec	a
	jr	NZ, 00161$
	ld	a, -24 (ix)
	ld	(hl), a
	C$sha1.c$130$2_1$55	= .
	.globl	C$sha1.c$130$2_1$55
;/work/source_code/testingfiles/sha1.c:130: for (int i = 7; i >= 0; i--) {
	dec	de
	jp	00112$
00109$:
	C$sha1.c$134$1_1$54	= .
	.globl	C$sha1.c$134$1_1$54
;/work/source_code/testingfiles/sha1.c:134: sha1_compress(ctx, ctx->buffer);
	ld	hl, #0x001c
	add	hl, bc
	push	hl
	push	bc
	call	_sha1_compress
	pop	af
	pop	af
	C$sha1.c$137$3_1$58	= .
	.globl	C$sha1.c$137$3_1$58
;/work/source_code/testingfiles/sha1.c:137: for (int i = 0; i < 5; i++) {
	ld	a, 4 (ix)
	ld	-8 (ix), a
	ld	a, 5 (ix)
	ld	-7 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00115$:
	ld	a, -2 (ix)
	sub	a, #0x05
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00117$
	C$sha1.c$138$3_1$58	= .
	.globl	C$sha1.c$138$3_1$58
;/work/source_code/testingfiles/sha1.c:138: out[i*4]   = (ctx->h[i] >> 24) & 0xFF;
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	ld	a, 6 (ix)
	add	a, c
	ld	-4 (ix), a
	ld	a, 7 (ix)
	adc	a, b
	ld	-3 (ix), a
	ld	a, -8 (ix)
	add	a, c
	ld	-6 (ix), a
	ld	a, -7 (ix)
	adc	a, b
	ld	-5 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	inc	hl
	inc	hl
	inc	hl
	ld	e, (hl)
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	(hl), e
	C$sha1.c$139$3_1$58	= .
	.globl	C$sha1.c$139$3_1$58
;/work/source_code/testingfiles/sha1.c:139: out[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
	ld	e, c
	ld	d, b
	inc	de
	ld	a, 6 (ix)
	add	a, e
	ld	-4 (ix), a
	ld	a, 7 (ix)
	adc	a, d
	ld	-3 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	inc	hl
	inc	hl
	inc	hl
	dec	hl
	ld	a, (hl)
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	(hl), a
	C$sha1.c$140$3_1$58	= .
	.globl	C$sha1.c$140$3_1$58
;/work/source_code/testingfiles/sha1.c:140: out[i*4+2] = (ctx->h[i] >> 8) & 0xFF;
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	ld	a, 6 (ix)
	add	a, e
	ld	e, a
	ld	a, 7 (ix)
	adc	a, d
	ld	d, a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	inc	hl
	ld	a, (hl)
	ld	(de), a
	C$sha1.c$141$3_1$58	= .
	.globl	C$sha1.c$141$3_1$58
;/work/source_code/testingfiles/sha1.c:141: out[i*4+3] = ctx->h[i] & 0xFF;
	inc	bc
	inc	bc
	inc	bc
	ld	e, b
	ld	a, 6 (ix)
	add	a, c
	ld	c, a
	ld	a, 7 (ix)
	adc	a, e
	ld	b, a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	ld	a, (hl)
	ld	(bc), a
	C$sha1.c$137$2_1$57	= .
	.globl	C$sha1.c$137$2_1$57
;/work/source_code/testingfiles/sha1.c:137: for (int i = 0; i < 5; i++) {
	inc	-2 (ix)
	jp	NZ,00115$
	inc	-1 (ix)
	jp	00115$
00117$:
	C$sha1.c$143$2_1$52	= .
	.globl	C$sha1.c$143$2_1$52
;/work/source_code/testingfiles/sha1.c:143: }
	ld	sp, ix
	pop	ix
	C$sha1.c$143$2_1$52	= .
	.globl	C$sha1.c$143$2_1$52
	XFsha1$sha1_final_alt$0$0	= .
	.globl	XFsha1$sha1_final_alt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$sha1.c$147$2_1$59	= .
	.globl	C$sha1.c$147$2_1$59
;/work/source_code/testingfiles/sha1.c:147: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-114
	add	hl, sp
	ld	sp, hl
	C$sha1.c$148$2_0$59	= .
	.globl	C$sha1.c$148$2_0$59
;/work/source_code/testingfiles/sha1.c:148: const char *msg = "The quick brown fox jumps over the lazy dog";
	C$sha1.c$152$1_0$59	= .
	.globl	C$sha1.c$152$1_0$59
;/work/source_code/testingfiles/sha1.c:152: sha1_init_alt(&ctx);
	ld	hl, #20
	add	hl, sp
	ex	de, hl
	ld	c, e
	ld	b, d
	push	de
	push	bc
	call	_sha1_init_alt
	pop	af
	pop	de
	C$sha1.c$153$1_0$59	= .
	.globl	C$sha1.c$153$1_0$59
;/work/source_code/testingfiles/sha1.c:153: sha1_update_alt(&ctx, (const uint8_t *)msg, strlen(msg));
	ld	hl, #___str_0
	push	hl
	call	_strlen
	pop	af
	ld	c, e
	ld	b, d
	push	de
	push	hl
	ld	hl, #___str_0
	push	hl
	push	bc
	call	_sha1_update_alt
	ld	hl, #6
	add	hl, sp
	ld	sp, hl
	pop	de
	C$sha1.c$154$1_0$59	= .
	.globl	C$sha1.c$154$1_0$59
;/work/source_code/testingfiles/sha1.c:154: sha1_final_alt(&ctx, digest);
	ld	hl, #0
	add	hl, sp
	push	hl
	push	hl
	push	de
	call	_sha1_final_alt
	pop	af
	ld	hl, #___str_2
	ex	(sp),hl
	call	_puts
	ld	hl, #___str_0
	ex	(sp),hl
	ld	hl, #___str_3
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	C$sha1.c$159$2_0$60	= .
	.globl	C$sha1.c$159$2_0$60
;/work/source_code/testingfiles/sha1.c:159: for (int i = 0; i < 20; i++)
	ld	de, #0x0000
00103$:
	ld	a, e
	sub	a, #0x14
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$sha1.c$160$2_0$60	= .
	.globl	C$sha1.c$160$2_0$60
;/work/source_code/testingfiles/sha1.c:160: printf("%02x", digest[i]);
	ld	l, c
	ld	h, b
	add	hl, de
	ld	l, (hl)
	ld	h, #0x00
	push	bc
	push	de
	push	hl
	ld	hl, #___str_4
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	de
	pop	bc
	C$sha1.c$159$2_0$60	= .
	.globl	C$sha1.c$159$2_0$60
;/work/source_code/testingfiles/sha1.c:159: for (int i = 0; i < 20; i++)
	inc	de
	jr	00103$
00101$:
	C$sha1.c$162$1_0$59	= .
	.globl	C$sha1.c$162$1_0$59
;/work/source_code/testingfiles/sha1.c:162: printf("\n");
	ld	hl, #___str_6
	push	hl
	call	_puts
	pop	af
	C$sha1.c$163$1_0$59	= .
	.globl	C$sha1.c$163$1_0$59
;/work/source_code/testingfiles/sha1.c:163: return 0;
	ld	hl, #0x0000
	C$sha1.c$164$1_0$59	= .
	.globl	C$sha1.c$164$1_0$59
;/work/source_code/testingfiles/sha1.c:164: }
	ld	sp, ix
	pop	ix
	C$sha1.c$164$1_0$59	= .
	.globl	C$sha1.c$164$1_0$59
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Fsha1$__str_0$0_0$0 == .
___str_0:
	.ascii "The quick brown fox jumps over the lazy dog"
	.db 0x00
Fsha1$__str_2$0_0$0 == .
___str_2:
	.ascii "Alternate SHA-1 Implementation"
	.db 0x00
Fsha1$__str_3$0_0$0 == .
___str_3:
	.ascii "Message: %s"
	.db 0x0a
	.ascii "SHA-1: "
	.db 0x00
Fsha1$__str_4$0_0$0 == .
___str_4:
	.ascii "%02x"
	.db 0x00
Fsha1$__str_6$0_0$0 == .
___str_6:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
