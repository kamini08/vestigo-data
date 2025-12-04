;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module xor
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _xor_stream
	.globl _xor_decrypt_block
	.globl _xor_encrypt_block
	.globl _xor_init
	.globl _strlen
	.globl _free
	.globl _malloc
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
	Fxor$rol$0$0	= .
	.globl	Fxor$rol$0$0
	C$xor.c$37$0_0$64	= .
	.globl	C$xor.c$37$0_0$64
;/work/source_code/testingfiles/xor.c:37: static inline uint8_t rol(uint8_t v, int s) {
;	---------------------------------
; Function rol
; ---------------------------------
_rol:
	C$xor.c$38$1_0$64	= .
	.globl	C$xor.c$38$1_0$64
;/work/source_code/testingfiles/xor.c:38: return (v << s) | (v >> (8 - s));
	ld	iy, #2
	add	iy, sp
	ld	e, 0 (iy)
	inc	iy
	ld	b, 0 (iy)
	inc	b
	jr	00104$
00103$:
	sla	e
00104$:
	djnz	00103$
	ld	c, 0 (iy)
	ld	a, #0x08
	sub	a, c
	ld	b, a
	dec	iy
	ld	c, 0 (iy)
	inc	b
	jr	00106$
00105$:
	srl	c
00106$:
	djnz	00105$
	ld	a, e
	or	a, c
	ld	l, a
	C$xor.c$39$1_0$64	= .
	.globl	C$xor.c$39$1_0$64
;/work/source_code/testingfiles/xor.c:39: }
	C$xor.c$39$1_0$64	= .
	.globl	C$xor.c$39$1_0$64
	XFxor$rol$0$0	= .
	.globl	XFxor$rol$0$0
	ret
Fxor$SBOX$0_0$0 == .
_SBOX:
	.db #0x6a	; 106	'j'
	.db #0x12	; 18
	.db #0xf3	; 243
	.db #0x88	; 136
	.db #0x0f	; 15
	.db #0x34	; 52	'4'
	.db #0xc5	; 197
	.db #0x7e	; 126
	.db #0x91	; 145
	.db #0x55	; 85	'U'
	.db #0xa2	; 162
	.db #0xce	; 206
	.db #0x1d	; 29
	.db #0xb8	; 184
	.db #0xe0	; 224
	.db #0x43	; 67	'C'
	.db #0x9c	; 156
	.db #0x01	; 1
	.db #0x6f	; 111	'o'
	.db #0xdd	; 221
	.db #0x84	; 132
	.db #0x23	; 35
	.db #0x5a	; 90	'Z'
	.db #0xbc	; 188
	.db #0x4e	; 78	'N'
	.db #0x67	; 103	'g'
	.db #0x11	; 17
	.db #0x02	; 2
	.db #0x98	; 152
	.db #0x76	; 118	'v'
	.db #0xaf	; 175
	.db #0xf9	; 249
	.db #0xc2	; 194
	.db #0x5d	; 93
	.db #0x7a	; 122	'z'
	.db #0x49	; 73	'I'
	.db #0xb1	; 177
	.db #0xea	; 234
	.db #0x0c	; 12
	.db #0x3e	; 62
	.db #0x82	; 130
	.db #0x14	; 20
	.db #0xf5	; 245
	.db #0x67	; 103	'g'
	.db #0x33	; 51	'3'
	.db #0xac	; 172
	.db #0x9f	; 159
	.db #0xd0	; 208
	.db #0x2a	; 42
	.db #0x51	; 81	'Q'
	.db #0x70	; 112	'p'
	.db #0xc9	; 201
	.db #0x0d	; 13
	.db #0xbe	; 190
	.db #0xe8	; 232
	.db #0x47	; 71	'G'
	.db #0x95	; 149
	.db #0x13	; 19
	.db #0x64	; 100	'd'
	.db #0x1f	; 31
	.db #0xc4	; 196
	.db #0x7b	; 123
	.db #0x22	; 34
	.db #0xda	; 218
	.db #0xe3	; 227
	.db #0xf0	; 240
	.db #0x28	; 40
	.db #0x8d	; 141
	.db #0x36	; 54	'6'
	.db #0x42	; 66	'B'
	.db #0xa9	; 169
	.db #0xcd	; 205
	.db #0x58	; 88	'X'
	.db #0x6c	; 108	'l'
	.db #0x0a	; 10
	.db #0x35	; 53	'5'
	.db #0xb7	; 183
	.db #0xf6	; 246
	.db #0x89	; 137
	.db #0x9e	; 158
	.db #0x65	; 101	'e'
	.db #0xc8	; 200
	.db #0x27	; 39
	.db #0xe4	; 228
	.db #0x0b	; 11
	.db #0x92	; 146
	.db #0xaf	; 175
	.db #0x4c	; 76	'L'
	.db #0x1a	; 26
	.db #0x7d	; 125
	.db #0x52	; 82	'R'
	.db #0xfc	; 252
	.db #0x33	; 51	'3'
	.db #0xe1	; 225
	.db #0xd4	; 212
	.db #0x0e	; 14
	.db #0xb3	; 179
	.db #0xa4	; 164
	.db #0x19	; 25
	.db #0x6b	; 107	'k'
	.db #0x87	; 135
	.db #0x54	; 84	'T'
	.db #0xfe	; 254
	.db #0x20	; 32
	.db #0xdc	; 220
	.db #0x3a	; 58
	.db #0x66	; 102	'f'
	.db #0x90	; 144
	.db #0xab	; 171
	.db #0x17	; 23
	.db #0x7c	; 124
	.db #0x48	; 72	'H'
	.db #0x11	; 17
	.db #0x62	; 98	'b'
	.db #0xc3	; 195
	.db #0x39	; 57	'9'
	.db #0xe9	; 233
	.db #0x05	; 5
	.db #0xb0	; 176
	.db #0x97	; 151
	.db #0x4f	; 79	'O'
	.db #0x81	; 129
	.db #0xf8	; 248
	.db #0x2f	; 47
	.db #0x0c	; 12
	.db #0xd1	; 209
	.db #0x25	; 37
	.db #0x76	; 118	'v'
	.db #0x59	; 89	'Y'
	.db #0x1c	; 28
	.db #0xa3	; 163
	.db #0x88	; 136
	.db #0x5f	; 95
	.db #0x6e	; 110	'n'
	.db #0x92	; 146
	.db #0x47	; 71	'G'
	.db #0xcb	; 203
	.db #0x3c	; 60
	.db #0xbd	; 189
	.db #0x04	; 4
	.db #0xe6	; 230
	.db #0x7a	; 122	'z'
	.db #0x55	; 85	'U'
	.db #0x9b	; 155
	.db #0x10	; 16
	.db #0xd9	; 217
	.db #0x2e	; 46
	.db #0xf1	; 241
	.db #0x68	; 104	'h'
	.db #0x4d	; 77	'M'
	.db #0xb5	; 181
	.db #0xac	; 172
	.db #0x32	; 50	'2'
	.db #0x03	; 3
	.db #0x91	; 145
	.db #0x7f	; 127
	.db #0xc7	; 199
	.db #0x58	; 88	'X'
	.db #0xe2	; 226
	.db #0x0a	; 10
	.db #0x40	; 64
	.db #0x29	; 41
	.db #0xdf	; 223
	.db #0x63	; 99	'c'
	.db #0x8c	; 140
	.db #0x12	; 18
	.db #0xfa	; 250
	.db #0xb6	; 182
	.db #0x35	; 53	'5'
	.db #0xee	; 238
	.db #0x57	; 87	'W'
	.db #0x03	; 3
	.db #0x94	; 148
	.db #0x7d	; 125
	.db #0xa1	; 161
	.db #0xc0	; 192
	.db #0xda	; 218
	.db #0x18	; 24
	.db #0x4b	; 75	'K'
	.db #0x6c	; 108	'l'
	.db #0xb2	; 178
	.db #0x0f	; 15
	.db #0x79	; 121	'y'
	.db #0x53	; 83	'S'
	.db #0xec	; 236
	.db #0x36	; 54	'6'
	.db #0xa7	; 167
	.db #0x91	; 145
	.db #0x08	; 8
	.db #0x62	; 98	'b'
	.db #0xdf	; 223
	.db #0xcb	; 203
	.db #0x14	; 20
	.db #0xc6	; 198
	.db #0x7e	; 126
	.db #0xf3	; 243
	.db #0x9a	; 154
	.db #0x55	; 85	'U'
	.db #0x81	; 129
	.db #0x24	; 36
	.db #0x39	; 57	'9'
	.db #0xd5	; 213
	.db #0xae	; 174
	.db #0x02	; 2
	.db #0xf7	; 247
	.db #0x60	; 96
	.db #0x48	; 72	'H'
	.db #0x8e	; 142
	.db #0x2c	; 44
	.db #0xd0	; 208
	.db #0x93	; 147
	.db #0x11	; 17
	.db #0xf4	; 244
	.db #0x3f	; 63
	.db #0x52	; 82	'R'
	.db #0xed	; 237
	.db #0x86	; 134
	.db #0xc1	; 193
	.db #0x79	; 121	'y'
	.db #0xbe	; 190
	.db #0x25	; 37
	.db #0x4a	; 74	'J'
	.db #0x07	; 7
	.db #0x94	; 148
	.db #0x64	; 100	'd'
	.db #0x27	; 39
	.db #0xd8	; 216
	.db #0x35	; 53	'5'
	.db #0xac	; 172
	.db #0xf2	; 242
	.db #0x8b	; 139
	.db #0x13	; 19
	.db #0x50	; 80	'P'
	.db #0xe7	; 231
	.db #0x9d	; 157
	.db #0x04	; 4
	.db #0x7a	; 122	'z'
	.db #0xca	; 202
	.db #0xb1	; 177
	.db #0x56	; 86	'V'
	.db #0x8f	; 143
	.db #0x05	; 5
	.db #0xd6	; 214
	.db #0xfe	; 254
	.db #0x21	; 33
	.db #0x90	; 144
	.db #0x34	; 52	'4'
	.db #0xc2	; 194
	.db #0x6a	; 106	'j'
	.db #0x49	; 73	'I'
	.db #0xbe	; 190
	.db #0x0d	; 13
	.db #0x78	; 120	'x'
	.db #0xe3	; 227
	.db #0x57	; 87	'W'
	.db #0x00	; 0
	G$xor_init$0$0	= .
	.globl	G$xor_init$0$0
	C$xor.c$42$1_0$66	= .
	.globl	C$xor.c$42$1_0$66
;/work/source_code/testingfiles/xor.c:42: void xor_init(XORCTX *c, const uint8_t *key) {
;	---------------------------------
; Function xor_init
; ---------------------------------
_xor_init::
	call	___sdcc_enter_ix
	ld	hl, #-11
	add	hl, sp
	ld	sp, hl
	C$xor.c$43$1_0$66	= .
	.globl	C$xor.c$43$1_0$66
;/work/source_code/testingfiles/xor.c:43: memcpy(c->master, key, XRKEY);
	ld	c, 4 (ix)
	ld	b, 5 (ix)
	ld	e, c
	ld	d, b
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	push	bc
	ld	bc, #0x0020
	ldir
	pop	bc
	C$xor.c$45$5_0$70	= .
	.globl	C$xor.c$45$5_0$70
;/work/source_code/testingfiles/xor.c:45: for (int r=0; r<XRROUND; r++) {
	ld	hl, #0x0020
	add	hl, bc
	ex	(sp), hl
	ld	bc, #0x0000
00108$:
	ld	a, c
	sub	a, #0x06
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00110$
	C$xor.c$46$5_0$70	= .
	.globl	C$xor.c$46$5_0$70
;/work/source_code/testingfiles/xor.c:46: for (int i=0; i<XRKEY; i++) {
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, bc
	add	hl, hl
	add	hl, hl
	add	hl, bc
	ld	-9 (ix), l
	ld	-8 (ix), h
	push	bc
	ld	hl, #0x0005
	push	hl
	push	bc
	call	__modsint
	pop	af
	pop	af
	pop	bc
	ld	-7 (ix), l
	ld	-6 (ix), h
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, -11 (ix)
	add	a, l
	ld	-5 (ix), a
	ld	a, -10 (ix)
	adc	a, h
	ld	-4 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00105$:
	ld	a, -2 (ix)
	sub	a, #0x20
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00109$
	C$xor.c$47$5_0$70	= .
	.globl	C$xor.c$47$5_0$70
;/work/source_code/testingfiles/xor.c:47: uint8_t v = key[(i + r) % XRKEY];
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	add	hl, bc
	push	bc
	ld	de, #0x0020
	push	de
	push	hl
	call	__modsint
	pop	af
	pop	af
	ex	de,hl
	pop	bc
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, de
	ld	a, (hl)
	ld	-3 (ix), a
	C$xor.c$48$5_0$70	= .
	.globl	C$xor.c$48$5_0$70
;/work/source_code/testingfiles/xor.c:48: v ^= SBOX[(i * 7 + r * 13) & 0xFF];
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	ld	l, e
	ld	h, d
	add	hl, hl
	add	hl, de
	add	hl, hl
	add	hl, de
	ld	e, -9 (ix)
	ld	d, -8 (ix)
	add	hl, de
	ld	h, #0x00
	ld	de, #_SBOX
	add	hl, de
	ld	a, (hl)
	xor	a, -3 (ix)
	ld	-3 (ix), a
	C$xor.c$49$6_0$71	= .
	.globl	C$xor.c$49$6_0$71
;/work/source_code/testingfiles/xor.c:49: v ^= rol(r + i, r % 5);
	ld	a, c
	ld	e, -2 (ix)
	add	a, e
	ld	e, a
	C$xor.c$38$8_0$73	= .
	.globl	C$xor.c$38$8_0$73
;/work/source_code/testingfiles/xor.c:38: return (v << s) | (v >> (8 - s));
	ld	l, e
	ld	a, -7 (ix)
	inc	a
	jr	00135$
00134$:
	sla	l
00135$:
	dec	a
	jr	NZ,00134$
	ld	d, -7 (ix)
	ld	a, #0x08
	sub	a, d
	inc	a
	jr	00137$
00136$:
	srl	e
00137$:
	dec	a
	jr	NZ, 00136$
	ld	a, l
	or	a, e
	C$xor.c$49$7_0$72	= .
	.globl	C$xor.c$49$7_0$72
;/work/source_code/testingfiles/xor.c:49: v ^= rol(r + i, r % 5);
	xor	a, -3 (ix)
	ld	e, a
	C$xor.c$50$5_0$70	= .
	.globl	C$xor.c$50$5_0$70
;/work/source_code/testingfiles/xor.c:50: c->rkey[r][i] = v;
	ld	a, -5 (ix)
	add	a, -2 (ix)
	ld	l, a
	ld	a, -4 (ix)
	adc	a, -1 (ix)
	ld	h, a
	ld	(hl), e
	C$xor.c$46$4_0$69	= .
	.globl	C$xor.c$46$4_0$69
;/work/source_code/testingfiles/xor.c:46: for (int i=0; i<XRKEY; i++) {
	inc	-2 (ix)
	jp	NZ,00105$
	inc	-1 (ix)
	jp	00105$
00109$:
	C$xor.c$45$2_0$67	= .
	.globl	C$xor.c$45$2_0$67
;/work/source_code/testingfiles/xor.c:45: for (int r=0; r<XRROUND; r++) {
	inc	bc
	jp	00108$
00110$:
	C$xor.c$53$2_0$66	= .
	.globl	C$xor.c$53$2_0$66
;/work/source_code/testingfiles/xor.c:53: }
	ld	sp, ix
	pop	ix
	C$xor.c$53$2_0$66	= .
	.globl	C$xor.c$53$2_0$66
	XG$xor_init$0$0	= .
	.globl	XG$xor_init$0$0
	ret
	Fxor$sub$0$0	= .
	.globl	Fxor$sub$0$0
	C$xor.c$56$2_0$76	= .
	.globl	C$xor.c$56$2_0$76
;/work/source_code/testingfiles/xor.c:56: static void sub(uint8_t *b) {
;	---------------------------------
; Function sub
; ---------------------------------
_sub:
	call	___sdcc_enter_ix
	C$xor.c$57$2_0$76	= .
	.globl	C$xor.c$57$2_0$76
;/work/source_code/testingfiles/xor.c:57: for (int i=0;i<XRBLOCK;i++) b[i] = SBOX[b[i]];
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00105$
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	inc	bc
	jr	00103$
00105$:
	C$xor.c$58$2_0$76	= .
	.globl	C$xor.c$58$2_0$76
;/work/source_code/testingfiles/xor.c:58: }
	pop	ix
	C$xor.c$58$2_0$76	= .
	.globl	C$xor.c$58$2_0$76
	XFxor$sub$0$0	= .
	.globl	XFxor$sub$0$0
	ret
	Fxor$perm$0$0	= .
	.globl	Fxor$perm$0$0
	C$xor.c$61$2_0$78	= .
	.globl	C$xor.c$61$2_0$78
;/work/source_code/testingfiles/xor.c:61: static void perm(uint8_t *b) {
;	---------------------------------
; Function perm
; ---------------------------------
_perm:
	call	___sdcc_enter_ix
	ld	hl, #-20
	add	hl, sp
	ld	sp, hl
	C$xor.c$63$2_0$79	= .
	.globl	C$xor.c$63$2_0$79
;/work/source_code/testingfiles/xor.c:63: for(int i=0;i<XRBLOCK;i++)
	ld	hl, #0
	add	hl, sp
	ld	-4 (ix), l
	ld	-3 (ix), h
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$xor.c$64$2_0$79	= .
	.globl	C$xor.c$64$2_0$79
;/work/source_code/testingfiles/xor.c:64: t[i] = b[(i*3 + 5) % XRBLOCK];
	ld	a, -4 (ix)
	add	a, c
	ld	-2 (ix), a
	ld	a, -3 (ix)
	adc	a, b
	ld	-1 (ix), a
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, bc
	ld	de, #0x0005
	add	hl, de
	push	bc
	ld	de, #0x0010
	push	de
	push	hl
	call	__modsint
	pop	af
	pop	af
	ex	de,hl
	pop	bc
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$xor.c$63$2_0$79	= .
	.globl	C$xor.c$63$2_0$79
;/work/source_code/testingfiles/xor.c:63: for(int i=0;i<XRBLOCK;i++)
	inc	bc
	jr	00103$
00101$:
	C$xor.c$65$1_0$78	= .
	.globl	C$xor.c$65$1_0$78
;/work/source_code/testingfiles/xor.c:65: memcpy(b,t,XRBLOCK);
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	ld	bc, #0x0010
	ldir
	C$xor.c$66$1_0$78	= .
	.globl	C$xor.c$66$1_0$78
;/work/source_code/testingfiles/xor.c:66: }
	ld	sp, ix
	pop	ix
	C$xor.c$66$1_0$78	= .
	.globl	C$xor.c$66$1_0$78
	XFxor$perm$0$0	= .
	.globl	XFxor$perm$0$0
	ret
	Fxor$diff$0$0	= .
	.globl	Fxor$diff$0$0
	C$xor.c$69$1_0$82	= .
	.globl	C$xor.c$69$1_0$82
;/work/source_code/testingfiles/xor.c:69: static void diff(uint8_t *b) {
;	---------------------------------
; Function diff
; ---------------------------------
_diff:
	call	___sdcc_enter_ix
	push	af
	push	af
	push	af
	C$xor.c$70$3_0$82	= .
	.globl	C$xor.c$70$3_0$82
;/work/source_code/testingfiles/xor.c:70: for(int i=0;i<XRBLOCK;i++){
	ld	bc, #0x0000
00104$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00106$
	C$xor.c$71$3_0$83	= .
	.globl	C$xor.c$71$3_0$83
;/work/source_code/testingfiles/xor.c:71: int p=(i+XRBLOCK-1)%XRBLOCK;
	ld	hl, #0x000f
	add	hl, bc
	push	bc
	ld	de, #0x0010
	push	de
	push	hl
	call	__modsint
	pop	af
	pop	af
	pop	bc
	inc	sp
	inc	sp
	push	hl
	C$xor.c$72$3_0$83	= .
	.globl	C$xor.c$72$3_0$83
;/work/source_code/testingfiles/xor.c:72: int n=(i+1)%XRBLOCK;
	ld	e, c
	ld	d, b
	inc	de
	push	bc
	push	de
	ld	hl, #0x0010
	push	hl
	push	de
	call	__modsint
	pop	af
	pop	af
	pop	de
	pop	bc
	ld	-4 (ix), l
	ld	-3 (ix), h
	C$xor.c$73$3_0$83	= .
	.globl	C$xor.c$73$3_0$83
;/work/source_code/testingfiles/xor.c:73: b[i] ^= rol(b[p],2) ^ (b[n]>>3);
	ld	a, 4 (ix)
	add	a, c
	ld	c, a
	ld	a, 5 (ix)
	adc	a, b
	ld	b, a
	ld	a, (bc)
	ld	-2 (ix), a
	ld	a, -6 (ix)
	add	a, 4 (ix)
	ld	l, a
	ld	a, -5 (ix)
	adc	a, 5 (ix)
	ld	h, a
	ld	a, (hl)
	C$xor.c$38$6_0$86	= .
	.globl	C$xor.c$38$6_0$86
;/work/source_code/testingfiles/xor.c:38: return (v << s) | (v >> (8 - s));
	ld	l, a
	sla	l
	sla	l
	rlca
	rlca
	and	a, #0x03
	or	a, l
	ld	-1 (ix), a
	C$xor.c$73$3_0$83	= .
	.globl	C$xor.c$73$3_0$83
;/work/source_code/testingfiles/xor.c:73: b[i] ^= rol(b[p],2) ^ (b[n]>>3);
	ld	a, -4 (ix)
	add	a, 4 (ix)
	ld	l, a
	ld	a, -3 (ix)
	adc	a, 5 (ix)
	ld	h, a
	ld	a, (hl)
	rrca
	rrca
	rrca
	and	a, #0x1f
	xor	a, -1 (ix)
	xor	a, -2 (ix)
	ld	(bc), a
	C$xor.c$70$2_0$82	= .
	.globl	C$xor.c$70$2_0$82
;/work/source_code/testingfiles/xor.c:70: for(int i=0;i<XRBLOCK;i++){
	ld	c, e
	ld	b, d
	jp	00104$
00106$:
	C$xor.c$75$2_0$82	= .
	.globl	C$xor.c$75$2_0$82
;/work/source_code/testingfiles/xor.c:75: }
	ld	sp, ix
	pop	ix
	C$xor.c$75$2_0$82	= .
	.globl	C$xor.c$75$2_0$82
	XFxor$diff$0$0	= .
	.globl	XFxor$diff$0$0
	ret
	G$xor_encrypt_block$0$0	= .
	.globl	G$xor_encrypt_block$0$0
	C$xor.c$78$2_0$88	= .
	.globl	C$xor.c$78$2_0$88
;/work/source_code/testingfiles/xor.c:78: void xor_encrypt_block(const uint8_t *in, uint8_t *out, XORCTX *c) {
;	---------------------------------
; Function xor_encrypt_block
; ---------------------------------
_xor_encrypt_block::
	call	___sdcc_enter_ix
	ld	hl, #-31
	add	hl, sp
	ld	sp, hl
	C$xor.c$80$1_0$88	= .
	.globl	C$xor.c$80$1_0$88
;/work/source_code/testingfiles/xor.c:80: memcpy(s,in,XRBLOCK);
	ld	hl, #0
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	e, c
	ld	d, b
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	bc
	ld	bc, #0x0010
	ldir
	pop	bc
	C$xor.c$82$4_0$91	= .
	.globl	C$xor.c$82$4_0$91
;/work/source_code/testingfiles/xor.c:82: for(int r=0;r<XRROUND;r++){
	ld	e, 8 (ix)
	ld	d, 9 (ix)
	ld	hl, #0x0020
	add	hl, de
	ld	-15 (ix), l
	ld	-14 (ix), h
	ld	-13 (ix), c
	ld	-12 (ix), b
	ld	-11 (ix), c
	ld	-10 (ix), b
	ld	-9 (ix), c
	ld	-8 (ix), b
	ld	de, #0x0000
00109$:
	ld	a, e
	sub	a, #0x06
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00104$
	C$xor.c$83$4_0$91	= .
	.globl	C$xor.c$83$4_0$91
;/work/source_code/testingfiles/xor.c:83: for(int i=0;i<XRBLOCK;i++)
	ld	l, e
	ld	h, d
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, l
	add	a, -15 (ix)
	ld	-7 (ix), a
	ld	a, h
	adc	a, -14 (ix)
	ld	-6 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00106$:
	ld	a, -2 (ix)
	sub	a, #0x10
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$xor.c$84$4_0$91	= .
	.globl	C$xor.c$84$4_0$91
;/work/source_code/testingfiles/xor.c:84: s[i] ^= c->rkey[r][i];
	ld	a, c
	add	a, -2 (ix)
	ld	-5 (ix), a
	ld	a, b
	adc	a, -1 (ix)
	ld	-4 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	ld	-3 (ix), a
	ld	a, -7 (ix)
	add	a, -2 (ix)
	ld	l, a
	ld	a, -6 (ix)
	adc	a, -1 (ix)
	ld	h, a
	ld	a, (hl)
	xor	a, -3 (ix)
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	(hl), a
	C$xor.c$83$4_0$91	= .
	.globl	C$xor.c$83$4_0$91
;/work/source_code/testingfiles/xor.c:83: for(int i=0;i<XRBLOCK;i++)
	inc	-2 (ix)
	jr	NZ,00106$
	inc	-1 (ix)
	jr	00106$
00101$:
	C$xor.c$86$3_0$90	= .
	.globl	C$xor.c$86$3_0$90
;/work/source_code/testingfiles/xor.c:86: sub(s);
	ld	l, -11 (ix)
	ld	h, -10 (ix)
	push	bc
	push	de
	push	hl
	call	_sub
	pop	af
	pop	de
	pop	bc
	C$xor.c$87$3_0$90	= .
	.globl	C$xor.c$87$3_0$90
;/work/source_code/testingfiles/xor.c:87: perm(s);
	ld	l, -9 (ix)
	ld	h, -8 (ix)
	push	bc
	push	de
	push	hl
	call	_perm
	pop	af
	pop	de
	pop	bc
	C$xor.c$88$3_0$90	= .
	.globl	C$xor.c$88$3_0$90
;/work/source_code/testingfiles/xor.c:88: if(r < XRROUND-1) diff(s);
	ld	a, e
	sub	a, #0x05
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00110$
	ld	l, -13 (ix)
	ld	h, -12 (ix)
	push	bc
	push	de
	push	hl
	call	_diff
	pop	af
	pop	de
	pop	bc
00110$:
	C$xor.c$82$2_0$89	= .
	.globl	C$xor.c$82$2_0$89
;/work/source_code/testingfiles/xor.c:82: for(int r=0;r<XRROUND;r++){
	inc	de
	jp	00109$
00104$:
	C$xor.c$90$1_0$88	= .
	.globl	C$xor.c$90$1_0$88
;/work/source_code/testingfiles/xor.c:90: memcpy(out,s,XRBLOCK);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
	C$xor.c$91$1_0$88	= .
	.globl	C$xor.c$91$1_0$88
;/work/source_code/testingfiles/xor.c:91: }
	ld	sp, ix
	pop	ix
	C$xor.c$91$1_0$88	= .
	.globl	C$xor.c$91$1_0$88
	XG$xor_encrypt_block$0$0	= .
	.globl	XG$xor_encrypt_block$0$0
	ret
	G$xor_decrypt_block$0$0	= .
	.globl	G$xor_decrypt_block$0$0
	C$xor.c$94$1_0$93	= .
	.globl	C$xor.c$94$1_0$93
;/work/source_code/testingfiles/xor.c:94: void xor_decrypt_block(const uint8_t *in, uint8_t *out, XORCTX *c) {
;	---------------------------------
; Function xor_decrypt_block
; ---------------------------------
_xor_decrypt_block::
	call	___sdcc_enter_ix
	ld	hl, #-52
	add	hl, sp
	ld	sp, hl
	C$xor.c$96$1_0$93	= .
	.globl	C$xor.c$96$1_0$93
;/work/source_code/testingfiles/xor.c:96: memcpy(s,in,XRBLOCK);
	ld	hl, #0
	add	hl, sp
	ld	-20 (ix), l
	ld	-19 (ix), h
	ex	de,hl
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	ld	bc, #0x0010
	ldir
	C$xor.c$98$4_0$96	= .
	.globl	C$xor.c$98$4_0$96
;/work/source_code/testingfiles/xor.c:98: for(int r=XRROUND-1;r>=0;r--){
	ld	a, -20 (ix)
	ld	-18 (ix), a
	ld	a, -19 (ix)
	ld	-17 (ix), a
	ld	hl, #16
	add	hl, sp
	ld	-16 (ix), l
	ld	-15 (ix), h
	ld	a, -20 (ix)
	ld	-14 (ix), a
	ld	a, -19 (ix)
	ld	-13 (ix), a
	ld	a, -16 (ix)
	ld	-12 (ix), a
	ld	a, -15 (ix)
	ld	-11 (ix), a
	ld	c, 8 (ix)
	ld	b, 9 (ix)
	ld	hl, #0x0020
	add	hl, bc
	ld	-10 (ix), l
	ld	-9 (ix), h
	ld	-4 (ix), #0x05
	xor	a, a
	ld	-3 (ix), a
00125$:
	bit	7, -3 (ix)
	jp	NZ, 00108$
	C$xor.c$99$1_0$93	= .
	.globl	C$xor.c$99$1_0$93
;/work/source_code/testingfiles/xor.c:99: for(int x=0;x<2;x++) diff(s); // approximate inverse
	ld	bc, #0x0000
00110$:
	ld	a, c
	sub	a, #0x02
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	ld	e, -18 (ix)
	ld	d, -17 (ix)
	push	bc
	push	de
	call	_diff
	pop	af
	pop	bc
	inc	bc
	jr	00110$
00101$:
	C$xor.c$102$1_0$93	= .
	.globl	C$xor.c$102$1_0$93
;/work/source_code/testingfiles/xor.c:102: for(int i=0;i<XRBLOCK;i++)
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00113$:
	ld	a, -2 (ix)
	sub	a, #0x10
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00102$
	C$xor.c$103$4_1$98	= .
	.globl	C$xor.c$103$4_1$98
;/work/source_code/testingfiles/xor.c:103: t[(i*3+5)%XRBLOCK] = s[i];
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	ld	l, c
	ld	h, b
	add	hl, hl
	add	hl, bc
	ld	-8 (ix), l
	ld	-7 (ix), h
	ld	a, -8 (ix)
	add	a, #0x05
	ld	-6 (ix), a
	ld	a, -7 (ix)
	adc	a, #0x00
	ld	-5 (ix), a
	ld	hl, #0x0010
	push	hl
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	a, -16 (ix)
	add	a, l
	ld	c, a
	ld	a, -15 (ix)
	adc	a, h
	ld	b, a
	ld	a, -20 (ix)
	add	a, -2 (ix)
	ld	e, a
	ld	a, -19 (ix)
	adc	a, -1 (ix)
	ld	d, a
	ld	a, (de)
	ld	(bc), a
	C$xor.c$102$4_1$98	= .
	.globl	C$xor.c$102$4_1$98
;/work/source_code/testingfiles/xor.c:102: for(int i=0;i<XRBLOCK;i++)
	inc	-2 (ix)
	jr	NZ,00113$
	inc	-1 (ix)
	jr	00113$
00102$:
	C$xor.c$104$3_1$97	= .
	.globl	C$xor.c$104$3_1$97
;/work/source_code/testingfiles/xor.c:104: memcpy(s,t,XRBLOCK);
	ld	e, -14 (ix)
	ld	d, -13 (ix)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	bc, #0x0010
	ldir
	C$xor.c$106$1_0$93	= .
	.globl	C$xor.c$106$1_0$93
;/work/source_code/testingfiles/xor.c:106: for(int i=0;i<XRBLOCK;i++)
	ld	bc, #0x0000
00119$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00106$
	C$xor.c$107$6_1$100	= .
	.globl	C$xor.c$107$6_1$100
;/work/source_code/testingfiles/xor.c:107: for(int k=0;k<256;k++)
	xor	a, a
	ld	-8 (ix), a
	ld	-7 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00116$:
	ld	a, -1 (ix)
	xor	a, #0x80
	sub	a, #0x81
	jr	NC,00120$
	C$xor.c$108$5_1$100	= .
	.globl	C$xor.c$108$5_1$100
;/work/source_code/testingfiles/xor.c:108: if(SBOX[k] == s[i]) { s[i]=k; break; }
	ld	a, #<(_SBOX)
	add	a, -2 (ix)
	ld	l, a
	ld	a, #>(_SBOX)
	adc	a, -1 (ix)
	ld	h, a
	ld	a, (hl)
	ld	-6 (ix), a
	ld	a, -20 (ix)
	add	a, c
	ld	e, a
	ld	a, -19 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	ld	-5 (ix), a
	ld	a, -6 (ix)
	sub	a, -5 (ix)
	jr	NZ,00117$
	ld	a, -8 (ix)
	ld	(de), a
	jr	00120$
00117$:
	C$xor.c$107$5_1$100	= .
	.globl	C$xor.c$107$5_1$100
;/work/source_code/testingfiles/xor.c:107: for(int k=0;k<256;k++)
	inc	-2 (ix)
	jr	NZ,00202$
	inc	-1 (ix)
00202$:
	ld	a, -2 (ix)
	ld	-8 (ix), a
	ld	a, -1 (ix)
	ld	-7 (ix), a
	jr	00116$
00120$:
	C$xor.c$106$4_1$99	= .
	.globl	C$xor.c$106$4_1$99
;/work/source_code/testingfiles/xor.c:106: for(int i=0;i<XRBLOCK;i++)
	inc	bc
	jr	00119$
00106$:
	C$xor.c$110$4_1$102	= .
	.globl	C$xor.c$110$4_1$102
;/work/source_code/testingfiles/xor.c:110: for(int i=0;i<XRBLOCK;i++)
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	ld	a, l
	add	a, -10 (ix)
	ld	-6 (ix), a
	ld	a, h
	adc	a, -9 (ix)
	ld	-5 (ix), a
	ld	bc, #0x0000
00122$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00126$
	C$xor.c$111$4_1$102	= .
	.globl	C$xor.c$111$4_1$102
;/work/source_code/testingfiles/xor.c:111: s[i] ^= c->rkey[r][i];
	ld	a, -20 (ix)
	add	a, c
	ld	e, a
	ld	a, -19 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	ld	-1 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	add	hl, bc
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	(de), a
	C$xor.c$110$4_1$102	= .
	.globl	C$xor.c$110$4_1$102
;/work/source_code/testingfiles/xor.c:110: for(int i=0;i<XRBLOCK;i++)
	inc	bc
	jr	00122$
00126$:
	C$xor.c$98$2_0$94	= .
	.globl	C$xor.c$98$2_0$94
;/work/source_code/testingfiles/xor.c:98: for(int r=XRROUND-1;r>=0;r--){
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	dec	hl
	ld	-4 (ix), l
	ld	-3 (ix), h
	jp	00125$
00108$:
	C$xor.c$113$1_0$93	= .
	.globl	C$xor.c$113$1_0$93
;/work/source_code/testingfiles/xor.c:113: memcpy(out,s,XRBLOCK);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, -20 (ix)
	ld	h, -19 (ix)
	ld	bc, #0x0010
	ldir
	C$xor.c$114$1_0$93	= .
	.globl	C$xor.c$114$1_0$93
;/work/source_code/testingfiles/xor.c:114: }
	ld	sp, ix
	pop	ix
	C$xor.c$114$1_0$93	= .
	.globl	C$xor.c$114$1_0$93
	XG$xor_decrypt_block$0$0	= .
	.globl	XG$xor_decrypt_block$0$0
	ret
	G$xor_stream$0$0	= .
	.globl	G$xor_stream$0$0
	C$xor.c$117$1_0$105	= .
	.globl	C$xor.c$117$1_0$105
;/work/source_code/testingfiles/xor.c:117: void xor_stream(const uint8_t *in, uint8_t *out, size_t len, XORCTX *c, uint64_t nonce) {
;	---------------------------------
; Function xor_stream
; ---------------------------------
_xor_stream::
	call	___sdcc_enter_ix
	ld	hl, #-56
	add	hl, sp
	ld	sp, hl
	C$xor.c$120$3_0$106	= .
	.globl	C$xor.c$120$3_0$106
;/work/source_code/testingfiles/xor.c:120: for(size_t i=0;i<len;i+=XRBLOCK) {
	ld	hl, #16
	add	hl, sp
	ld	-16 (ix), l
	ld	-15 (ix), h
	ld	a, -16 (ix)
	add	a, #0x08
	ld	-14 (ix), a
	ld	a, -15 (ix)
	adc	a, #0x00
	ld	-13 (ix), a
	ld	hl, #0
	add	hl, sp
	ld	-12 (ix), l
	ld	-11 (ix), h
	ld	a, -16 (ix)
	ld	-10 (ix), a
	ld	a, -15 (ix)
	ld	-9 (ix), a
	xor	a, a
	ld	-8 (ix), a
	ld	-7 (ix), a
00107$:
	ld	a, -8 (ix)
	sub	a, 8 (ix)
	ld	a, -7 (ix)
	sbc	a, 9 (ix)
	jp	NC, 00109$
	C$xor.c$121$3_0$106	= .
	.globl	C$xor.c$121$3_0$106
;/work/source_code/testingfiles/xor.c:121: uint64_t blk = i / XRBLOCK;
	ld	c, -8 (ix)
	ld	e, -7 (ix)
	ld	b, #0x04
00140$:
	srl	e
	rr	c
	djnz	00140$
	ld	-24 (ix), c
	ld	-23 (ix), e
	xor	a, a
	ld	-22 (ix), a
	ld	-21 (ix), a
	ld	-20 (ix), a
	ld	-19 (ix), a
	ld	-18 (ix), a
	ld	-17 (ix), a
	C$xor.c$122$3_0$106	= .
	.globl	C$xor.c$122$3_0$106
;/work/source_code/testingfiles/xor.c:122: memcpy(ctr,&nonce,8);
	ld	e, -16 (ix)
	ld	d, -15 (ix)
	ld	hl, #68
	add	hl, sp
	ld	bc, #0x0008
	ldir
	C$xor.c$123$3_0$106	= .
	.globl	C$xor.c$123$3_0$106
;/work/source_code/testingfiles/xor.c:123: memcpy(ctr+8,&blk,8);
	ld	e, -14 (ix)
	ld	d, -13 (ix)
	ld	hl, #32
	add	hl, sp
	ld	bc, #0x0008
	ldir
	C$xor.c$125$3_0$106	= .
	.globl	C$xor.c$125$3_0$106
;/work/source_code/testingfiles/xor.c:125: xor_encrypt_block(ctr,ks,c);
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	ld	c, -10 (ix)
	ld	b, -9 (ix)
	ld	l, 10 (ix)
	ld	h, 11 (ix)
	push	hl
	push	de
	push	bc
	call	_xor_encrypt_block
	pop	af
	pop	af
	pop	af
	C$xor.c$127$2_0$105	= .
	.globl	C$xor.c$127$2_0$105
;/work/source_code/testingfiles/xor.c:127: size_t n = (i+XRBLOCK>len)? len-i : XRBLOCK;
	ld	a, -8 (ix)
	add	a, #0x10
	ld	-6 (ix), a
	ld	a, -7 (ix)
	adc	a, #0x00
	ld	-5 (ix), a
	ld	a, 8 (ix)
	sub	a, -6 (ix)
	ld	a, 9 (ix)
	sbc	a, -5 (ix)
	jr	NC,00111$
	ld	a, 8 (ix)
	sub	a, -8 (ix)
	ld	-2 (ix), a
	ld	a, 9 (ix)
	sbc	a, -7 (ix)
	ld	-1 (ix), a
	jr	00112$
00111$:
	ld	-2 (ix), #0x10
	xor	a, a
	ld	-1 (ix), a
00112$:
	ld	a, -2 (ix)
	ld	-4 (ix), a
	ld	a, -1 (ix)
	ld	-3 (ix), a
	C$xor.c$128$2_0$105	= .
	.globl	C$xor.c$128$2_0$105
;/work/source_code/testingfiles/xor.c:128: for(size_t j=0;j<n;j++)
	ld	de, #0x0000
00104$:
	ld	a, e
	sub	a, -4 (ix)
	ld	a, d
	sbc	a, -3 (ix)
	jr	NC,00108$
	C$xor.c$129$4_1$108	= .
	.globl	C$xor.c$129$4_1$108
;/work/source_code/testingfiles/xor.c:129: out[i+j] = in[i+j] ^ ks[j];
	ld	a, -8 (ix)
	add	a, e
	ld	c, a
	ld	a, -7 (ix)
	adc	a, d
	ld	b, a
	ld	a, 6 (ix)
	add	a, c
	ld	-2 (ix), a
	ld	a, 7 (ix)
	adc	a, b
	ld	-1 (ix), a
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, bc
	ld	c, (hl)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	add	hl, de
	ld	a, (hl)
	xor	a, c
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$xor.c$128$4_1$108	= .
	.globl	C$xor.c$128$4_1$108
;/work/source_code/testingfiles/xor.c:128: for(size_t j=0;j<n;j++)
	inc	de
	jr	00104$
00108$:
	C$xor.c$120$2_0$105	= .
	.globl	C$xor.c$120$2_0$105
;/work/source_code/testingfiles/xor.c:120: for(size_t i=0;i<len;i+=XRBLOCK) {
	ld	a, -6 (ix)
	ld	-8 (ix), a
	ld	a, -5 (ix)
	ld	-7 (ix), a
	jp	00107$
00109$:
	C$xor.c$131$2_0$105	= .
	.globl	C$xor.c$131$2_0$105
;/work/source_code/testingfiles/xor.c:131: }
	ld	sp, ix
	pop	ix
	C$xor.c$131$2_0$105	= .
	.globl	C$xor.c$131$2_0$105
	XG$xor_stream$0$0	= .
	.globl	XG$xor_stream$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$xor.c$134$2_0$109	= .
	.globl	C$xor.c$134$2_0$109
;/work/source_code/testingfiles/xor.c:134: int main(){
;	---------------------------------
; Function main
; ---------------------------------
_main::
	call	___sdcc_enter_ix
	ld	hl, #-312
	add	hl, sp
	ld	sp, hl
	C$xor.c$137$2_0$110	= .
	.globl	C$xor.c$137$2_0$110
;/work/source_code/testingfiles/xor.c:137: for(i=0;i<XRKEY;i++) key[i]=i*4;
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	bc, #0x0000
00106$:
	ld	l, e
	ld	h, d
	add	hl, bc
	ld	a, c
	add	a, a
	add	a, a
	ld	(hl), a
	inc	bc
	ld	a, c
	sub	a, #0x20
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	C,00106$
	C$xor.c$140$1_1$111	= .
	.globl	C$xor.c$140$1_1$111
;/work/source_code/testingfiles/xor.c:140: xor_init(&ctx,key);
	ld	hl, #32
	add	hl, sp
	ld	-8 (ix), l
	ld	-7 (ix), h
	push	de
	push	hl
	call	_xor_init
	pop	af
	pop	af
	C$xor.c$142$2_1$112	= .
	.globl	C$xor.c$142$2_1$112
;/work/source_code/testingfiles/xor.c:142: uint8_t pt[XRBLOCK] = "XorCipher Test!";
	ld	hl, #256
	add	hl, sp
	ex	de, hl
	ld	a, #0x58
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x6f
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0x72
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0x43
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0x69
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x70
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x68
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x65
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0x72
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x20
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0x54
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x65
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x73
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x74
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x21
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0x00
	C$xor.c$145$1_2$112	= .
	.globl	C$xor.c$145$1_2$112
;/work/source_code/testingfiles/xor.c:145: printf("Alternate XOR Cipher (Simple)\n\n");
	push	de
	ld	hl, #___str_3
	push	hl
	call	_puts
	pop	af
	pop	de
	C$xor.c$147$1_2$112	= .
	.globl	C$xor.c$147$1_2$112
;/work/source_code/testingfiles/xor.c:147: xor_encrypt_block(pt,ct,&ctx);
	ld	c, -8 (ix)
	ld	b, -7 (ix)
	ld	hl, #272
	add	hl, sp
	ld	-6 (ix), l
	ld	-5 (ix), h
	ld	a, -6 (ix)
	ld	-2 (ix), a
	ld	a, -5 (ix)
	ld	-1 (ix), a
	ld	l, e
	ld	h, d
	push	de
	push	bc
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	push	bc
	push	hl
	call	_xor_encrypt_block
	pop	af
	pop	af
	pop	af
	pop	de
	C$xor.c$148$1_2$112	= .
	.globl	C$xor.c$148$1_2$112
;/work/source_code/testingfiles/xor.c:148: xor_decrypt_block(ct,dt,&ctx);
	ld	c, -8 (ix)
	ld	b, -7 (ix)
	ld	hl, #288
	add	hl, sp
	ld	-4 (ix), l
	ld	-3 (ix), h
	ld	a, -4 (ix)
	ld	-2 (ix), a
	ld	a, -3 (ix)
	ld	-1 (ix), a
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	de
	push	bc
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	push	bc
	push	hl
	call	_xor_decrypt_block
	pop	af
	pop	af
	ld	hl, #___str_5
	ex	(sp),hl
	call	_puts
	ld	hl, #___str_6
	ex	(sp),hl
	call	_printf
	pop	af
	pop	de
	C$xor.c$152$2_2$113	= .
	.globl	C$xor.c$152$2_2$113
;/work/source_code/testingfiles/xor.c:152: for(i=0;i<XRBLOCK;i++) printf("%02x ",pt[i]); printf("\n");
	ld	bc, #0x0000
00108$:
	ld	l, e
	ld	h, d
	add	hl, bc
	ld	l, (hl)
	ld	h, #0x00
	push	bc
	push	de
	push	hl
	ld	hl, #___str_7
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	de
	pop	bc
	inc	bc
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	C,00108$
	ld	hl, #___str_9
	push	hl
	call	_puts
	C$xor.c$153$1_2$112	= .
	.globl	C$xor.c$153$1_2$112
;/work/source_code/testingfiles/xor.c:153: printf("Cipher: ");
	ld	hl, #___str_10
	ex	(sp),hl
	call	_printf
	pop	af
	C$xor.c$154$2_2$114	= .
	.globl	C$xor.c$154$2_2$114
;/work/source_code/testingfiles/xor.c:154: for(i=0;i<XRBLOCK;i++) printf("%02x ",ct[i]); printf("\n");
	ld	bc, #0x0000
00110$:
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_7
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	inc	bc
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	C,00110$
	ld	hl, #___str_9
	push	hl
	call	_puts
	C$xor.c$155$1_2$112	= .
	.globl	C$xor.c$155$1_2$112
;/work/source_code/testingfiles/xor.c:155: printf("Dec   : ");
	ld	hl, #___str_12
	ex	(sp),hl
	call	_printf
	pop	af
	C$xor.c$156$2_2$115	= .
	.globl	C$xor.c$156$2_2$115
;/work/source_code/testingfiles/xor.c:156: for(i=0;i<XRBLOCK;i++) printf("%02x ",dt[i]); printf("\n\n");
	ld	bc, #0x0000
00112$:
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_7
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	inc	bc
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	C,00112$
	ld	hl, #___str_14
	push	hl
	call	_puts
	C$xor.c$158$2_2$116	= .
	.globl	C$xor.c$158$2_2$116
;/work/source_code/testingfiles/xor.c:158: const char *msg="Alternate XOR CTR stream mode works!";
	C$xor.c$159$1_3$116	= .
	.globl	C$xor.c$159$1_3$116
;/work/source_code/testingfiles/xor.c:159: size_t L=strlen(msg);
	ld	hl, #___str_1
	ex	(sp),hl
	call	_strlen
	pop	af
	C$xor.c$160$1_3$116	= .
	.globl	C$xor.c$160$1_3$116
;/work/source_code/testingfiles/xor.c:160: uint8_t *sc=malloc(L), *sd=malloc(L);
	ld	-6 (ix), l
	ld	-5 (ix), h
	push	hl
	call	_malloc
	pop	af
	ld	-4 (ix), l
	ld	-3 (ix), h
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	call	_malloc
	pop	af
	ld	-2 (ix), l
	ld	-1 (ix), h
	C$xor.c$162$1_3$116	= .
	.globl	C$xor.c$162$1_3$116
;/work/source_code/testingfiles/xor.c:162: xor_stream((uint8_t*)msg,sc,L,&ctx,0xAABBCCDDEEFF0011ULL);
	ld	c, -8 (ix)
	ld	b, -7 (ix)
	ld	de, #0xaabb
	push	de
	ld	de, #0xccdd
	push	de
	ld	de, #0xeeff
	push	de
	ld	de, #0x0011
	push	de
	push	bc
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	ld	hl, #___str_1
	push	hl
	call	_xor_stream
	ld	hl, #16
	add	hl, sp
	ld	sp, hl
	C$xor.c$163$1_3$116	= .
	.globl	C$xor.c$163$1_3$116
;/work/source_code/testingfiles/xor.c:163: xor_stream(sc,sd,L,&ctx,0xAABBCCDDEEFF0011ULL);
	ld	c, -8 (ix)
	ld	b, -7 (ix)
	ld	de, #0xaabb
	push	de
	ld	de, #0xccdd
	push	de
	ld	de, #0xeeff
	push	de
	ld	de, #0x0011
	push	de
	push	bc
	ld	l, -6 (ix)
	ld	h, -5 (ix)
	push	hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	hl
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	hl
	call	_xor_stream
	ld	hl, #16
	add	hl, sp
	ld	sp, hl
	C$xor.c$165$1_3$116	= .
	.globl	C$xor.c$165$1_3$116
;/work/source_code/testingfiles/xor.c:165: printf("Stream Encrypted: ");
	ld	hl, #___str_15
	push	hl
	call	_printf
	pop	af
	C$xor.c$166$2_3$117	= .
	.globl	C$xor.c$166$2_3$117
;/work/source_code/testingfiles/xor.c:166: for(size_t i=0;i<L;i++) printf("%02x",sc[i]);
	ld	bc, #0x0000
00115$:
	ld	a, c
	sub	a, -6 (ix)
	ld	a, b
	sbc	a, -5 (ix)
	jr	NC,00105$
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_16
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	inc	bc
	jr	00115$
00105$:
	C$xor.c$167$1_3$116	= .
	.globl	C$xor.c$167$1_3$116
;/work/source_code/testingfiles/xor.c:167: printf("\n");
	ld	hl, #___str_14
	push	hl
	call	_printf
	pop	af
	C$xor.c$169$1_3$116	= .
	.globl	C$xor.c$169$1_3$116
;/work/source_code/testingfiles/xor.c:169: printf("Stream Decrypted: %s\n", sd);
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	hl
	ld	hl, #___str_17
	push	hl
	call	_printf
	pop	af
	pop	af
	C$xor.c$171$1_3$116	= .
	.globl	C$xor.c$171$1_3$116
;/work/source_code/testingfiles/xor.c:171: free(sc); free(sd);
	ld	c, -4 (ix)
	ld	b, -3 (ix)
	push	bc
	call	_free
	pop	af
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	push	bc
	call	_free
	C$xor.c$172$1_3$109	= .
	.globl	C$xor.c$172$1_3$109
;/work/source_code/testingfiles/xor.c:172: }
	ld	sp,ix
	pop	ix
	C$xor.c$172$1_3$109	= .
	.globl	C$xor.c$172$1_3$109
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Fxor$__str_1$0_0$0 == .
___str_1:
	.ascii "Alternate XOR CTR stream mode works!"
	.db 0x00
Fxor$__str_3$0_0$0 == .
___str_3:
	.ascii "Alternate XOR Cipher (Simple)"
	.db 0x0a
	.db 0x00
Fxor$__str_5$0_0$0 == .
___str_5:
	.ascii "Block:"
	.db 0x00
Fxor$__str_6$0_0$0 == .
___str_6:
	.ascii "Plain : "
	.db 0x00
Fxor$__str_7$0_0$0 == .
___str_7:
	.ascii "%02x "
	.db 0x00
Fxor$__str_9$0_0$0 == .
___str_9:
	.db 0x00
Fxor$__str_10$0_0$0 == .
___str_10:
	.ascii "Cipher: "
	.db 0x00
Fxor$__str_12$0_0$0 == .
___str_12:
	.ascii "Dec   : "
	.db 0x00
Fxor$__str_14$0_0$0 == .
___str_14:
	.db 0x0a
	.db 0x00
Fxor$__str_15$0_0$0 == .
___str_15:
	.ascii "Stream Encrypted: "
	.db 0x00
Fxor$__str_16$0_0$0 == .
___str_16:
	.ascii "%02x"
	.db 0x00
Fxor$__str_17$0_0$0 == .
___str_17:
	.ascii "Stream Decrypted: %s"
	.db 0x0a
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
