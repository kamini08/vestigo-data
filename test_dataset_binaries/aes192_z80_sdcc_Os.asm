;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module aes192
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _AES192_Encrypt
	.globl _puts
	.globl _printf
	.globl _putchar
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
	G$putchar$0$0	= .
	.globl	G$putchar$0$0
	C$aes192.c$6$0_0$35	= .
	.globl	C$aes192.c$6$0_0$35
;/work/source_code/testingfiles/aes192.c:6: int putchar(int c) { (void)c; return c; }
;	---------------------------------
; Function putchar
; ---------------------------------
_putchar::
	pop	bc
	pop	hl
	push	hl
	push	bc
	C$aes192.c$6$1_0$35	= .
	.globl	C$aes192.c$6$1_0$35
	XG$putchar$0$0	= .
	.globl	XG$putchar$0$0
	ret
	Faes192$xt$0$0	= .
	.globl	Faes192$xt$0$0
	C$aes192.c$36$1_0$37	= .
	.globl	C$aes192.c$36$1_0$37
;/work/source_code/testingfiles/aes192.c:36: static uint8_t xt(uint8_t x) {
;	---------------------------------
; Function xt
; ---------------------------------
_xt:
	call	___sdcc_enter_ix
	C$aes192.c$37$1_0$37	= .
	.globl	C$aes192.c$37$1_0$37
;/work/source_code/testingfiles/aes192.c:37: return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
	ld	a, 4 (ix)
	add	a, a
	ld	c, a
	ld	a, 4 (ix)
	rlca
	jr	NC,00103$
	ld	de, #0x001b
	jr	00104$
00103$:
	ld	de, #0x0000
00104$:
	ld	a, c
	rla
	sbc	a, a
	push	af
	ld	a, c
	xor	a, e
	ld	l, a
	pop	af
	xor	a, d
	C$aes192.c$38$1_0$37	= .
	.globl	C$aes192.c$38$1_0$37
;/work/source_code/testingfiles/aes192.c:38: }
	pop	ix
	C$aes192.c$38$1_0$37	= .
	.globl	C$aes192.c$38$1_0$37
	XFaes192$xt$0$0	= .
	.globl	XFaes192$xt$0$0
	ret
Faes192$SBOX$0_0$0 == .
_SBOX:
	.db #0x63	; 99	'c'
	.db #0x7c	; 124
	.db #0x77	; 119	'w'
	.db #0x7b	; 123
	.db #0xf2	; 242
	.db #0x6b	; 107	'k'
	.db #0x6f	; 111	'o'
	.db #0xc5	; 197
	.db #0x30	; 48	'0'
	.db #0x01	; 1
	.db #0x67	; 103	'g'
	.db #0x2b	; 43
	.db #0xfe	; 254
	.db #0xd7	; 215
	.db #0xab	; 171
	.db #0x76	; 118	'v'
	.db #0xca	; 202
	.db #0x82	; 130
	.db #0xc9	; 201
	.db #0x7d	; 125
	.db #0xfa	; 250
	.db #0x59	; 89	'Y'
	.db #0x47	; 71	'G'
	.db #0xf0	; 240
	.db #0xad	; 173
	.db #0xd4	; 212
	.db #0xa2	; 162
	.db #0xaf	; 175
	.db #0x9c	; 156
	.db #0xa4	; 164
	.db #0x72	; 114	'r'
	.db #0xc0	; 192
	.db #0xb7	; 183
	.db #0xfd	; 253
	.db #0x93	; 147
	.db #0x26	; 38
	.db #0x36	; 54	'6'
	.db #0x3f	; 63
	.db #0xf7	; 247
	.db #0xcc	; 204
	.db #0x34	; 52	'4'
	.db #0xa5	; 165
	.db #0xe5	; 229
	.db #0xf1	; 241
	.db #0x71	; 113	'q'
	.db #0xd8	; 216
	.db #0x31	; 49	'1'
	.db #0x15	; 21
	.db #0x04	; 4
	.db #0xc7	; 199
	.db #0x23	; 35
	.db #0xc3	; 195
	.db #0x18	; 24
	.db #0x96	; 150
	.db #0x05	; 5
	.db #0x9a	; 154
	.db #0x07	; 7
	.db #0x12	; 18
	.db #0x80	; 128
	.db #0xe2	; 226
	.db #0xeb	; 235
	.db #0x27	; 39
	.db #0xb2	; 178
	.db #0x75	; 117	'u'
	.db #0x09	; 9
	.db #0x83	; 131
	.db #0x2c	; 44
	.db #0x1a	; 26
	.db #0x1b	; 27
	.db #0x6e	; 110	'n'
	.db #0x5a	; 90	'Z'
	.db #0xa0	; 160
	.db #0x52	; 82	'R'
	.db #0x3b	; 59
	.db #0xd6	; 214
	.db #0xb3	; 179
	.db #0x29	; 41
	.db #0xe3	; 227
	.db #0x2f	; 47
	.db #0x84	; 132
	.db #0x53	; 83	'S'
	.db #0xd1	; 209
	.db #0x00	; 0
	.db #0xed	; 237
	.db #0x20	; 32
	.db #0xfc	; 252
	.db #0xb1	; 177
	.db #0x5b	; 91
	.db #0x6a	; 106	'j'
	.db #0xcb	; 203
	.db #0xbe	; 190
	.db #0x39	; 57	'9'
	.db #0x4a	; 74	'J'
	.db #0x4c	; 76	'L'
	.db #0x58	; 88	'X'
	.db #0xcf	; 207
	.db #0xd0	; 208
	.db #0xef	; 239
	.db #0xaa	; 170
	.db #0xfb	; 251
	.db #0x43	; 67	'C'
	.db #0x4d	; 77	'M'
	.db #0x33	; 51	'3'
	.db #0x85	; 133
	.db #0x45	; 69	'E'
	.db #0xf9	; 249
	.db #0x02	; 2
	.db #0x7f	; 127
	.db #0x50	; 80	'P'
	.db #0x3c	; 60
	.db #0x9f	; 159
	.db #0xa8	; 168
	.db #0x51	; 81	'Q'
	.db #0xa3	; 163
	.db #0x40	; 64
	.db #0x8f	; 143
	.db #0x92	; 146
	.db #0x9d	; 157
	.db #0x38	; 56	'8'
	.db #0xf5	; 245
	.db #0xbc	; 188
	.db #0xb6	; 182
	.db #0xda	; 218
	.db #0x21	; 33
	.db #0x10	; 16
	.db #0xff	; 255
	.db #0xf3	; 243
	.db #0xd2	; 210
	.db #0xcd	; 205
	.db #0x0c	; 12
	.db #0x13	; 19
	.db #0xec	; 236
	.db #0x5f	; 95
	.db #0x97	; 151
	.db #0x44	; 68	'D'
	.db #0x17	; 23
	.db #0xc4	; 196
	.db #0xa7	; 167
	.db #0x7e	; 126
	.db #0x3d	; 61
	.db #0x64	; 100	'd'
	.db #0x5d	; 93
	.db #0x19	; 25
	.db #0x73	; 115	's'
	.db #0x60	; 96
	.db #0x81	; 129
	.db #0x4f	; 79	'O'
	.db #0xdc	; 220
	.db #0x22	; 34
	.db #0x2a	; 42
	.db #0x90	; 144
	.db #0x88	; 136
	.db #0x46	; 70	'F'
	.db #0xee	; 238
	.db #0xb8	; 184
	.db #0x14	; 20
	.db #0xde	; 222
	.db #0x5e	; 94
	.db #0x0b	; 11
	.db #0xdb	; 219
	.db #0xe0	; 224
	.db #0x32	; 50	'2'
	.db #0x3a	; 58
	.db #0x0a	; 10
	.db #0x49	; 73	'I'
	.db #0x06	; 6
	.db #0x24	; 36
	.db #0x5c	; 92
	.db #0xc2	; 194
	.db #0xd3	; 211
	.db #0xac	; 172
	.db #0x62	; 98	'b'
	.db #0x91	; 145
	.db #0x95	; 149
	.db #0xe4	; 228
	.db #0x79	; 121	'y'
	.db #0xe7	; 231
	.db #0xc8	; 200
	.db #0x37	; 55	'7'
	.db #0x6d	; 109	'm'
	.db #0x8d	; 141
	.db #0xd5	; 213
	.db #0x4e	; 78	'N'
	.db #0xa9	; 169
	.db #0x6c	; 108	'l'
	.db #0x56	; 86	'V'
	.db #0xf4	; 244
	.db #0xea	; 234
	.db #0x65	; 101	'e'
	.db #0x7a	; 122	'z'
	.db #0xae	; 174
	.db #0x08	; 8
	.db #0xba	; 186
	.db #0x78	; 120	'x'
	.db #0x25	; 37
	.db #0x2e	; 46
	.db #0x1c	; 28
	.db #0xa6	; 166
	.db #0xb4	; 180
	.db #0xc6	; 198
	.db #0xe8	; 232
	.db #0xdd	; 221
	.db #0x74	; 116	't'
	.db #0x1f	; 31
	.db #0x4b	; 75	'K'
	.db #0xbd	; 189
	.db #0x8b	; 139
	.db #0x8a	; 138
	.db #0x70	; 112	'p'
	.db #0x3e	; 62
	.db #0xb5	; 181
	.db #0x66	; 102	'f'
	.db #0x48	; 72	'H'
	.db #0x03	; 3
	.db #0xf6	; 246
	.db #0x0e	; 14
	.db #0x61	; 97	'a'
	.db #0x35	; 53	'5'
	.db #0x57	; 87	'W'
	.db #0xb9	; 185
	.db #0x86	; 134
	.db #0xc1	; 193
	.db #0x1d	; 29
	.db #0x9e	; 158
	.db #0xe1	; 225
	.db #0xf8	; 248
	.db #0x98	; 152
	.db #0x11	; 17
	.db #0x69	; 105	'i'
	.db #0xd9	; 217
	.db #0x8e	; 142
	.db #0x94	; 148
	.db #0x9b	; 155
	.db #0x1e	; 30
	.db #0x87	; 135
	.db #0xe9	; 233
	.db #0xce	; 206
	.db #0x55	; 85	'U'
	.db #0x28	; 40
	.db #0xdf	; 223
	.db #0x8c	; 140
	.db #0xa1	; 161
	.db #0x89	; 137
	.db #0x0d	; 13
	.db #0xbf	; 191
	.db #0xe6	; 230
	.db #0x42	; 66	'B'
	.db #0x68	; 104	'h'
	.db #0x41	; 65	'A'
	.db #0x99	; 153
	.db #0x2d	; 45
	.db #0x0f	; 15
	.db #0xb0	; 176
	.db #0x54	; 84	'T'
	.db #0xbb	; 187
	.db #0x16	; 22
Faes192$RCON$0_0$0 == .
_RCON:
	.db #0x00	; 0
	.db #0x01	; 1
	.db #0x02	; 2
	.db #0x04	; 4
	.db #0x08	; 8
	.db #0x10	; 16
	.db #0x20	; 32
	.db #0x40	; 64
	.db #0x80	; 128
	.db #0x1b	; 27
	.db #0x36	; 54	'6'
	.db #0x6c	; 108	'l'
	.db #0xd8	; 216
	Faes192$SubBytes$0$0	= .
	.globl	Faes192$SubBytes$0$0
	C$aes192.c$40$1_0$40	= .
	.globl	C$aes192.c$40$1_0$40
;/work/source_code/testingfiles/aes192.c:40: static void SubBytes(uint8_t *s) {
;	---------------------------------
; Function SubBytes
; ---------------------------------
_SubBytes:
	call	___sdcc_enter_ix
	C$aes192.c$41$2_0$40	= .
	.globl	C$aes192.c$41$2_0$40
;/work/source_code/testingfiles/aes192.c:41: for(int i=0;i<16;i++)
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
	C$aes192.c$42$2_0$40	= .
	.globl	C$aes192.c$42$2_0$40
;/work/source_code/testingfiles/aes192.c:42: s[i] = SBOX[s[i]];
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
	C$aes192.c$41$2_0$40	= .
	.globl	C$aes192.c$41$2_0$40
;/work/source_code/testingfiles/aes192.c:41: for(int i=0;i<16;i++)
	inc	bc
	jr	00103$
00105$:
	C$aes192.c$43$2_0$40	= .
	.globl	C$aes192.c$43$2_0$40
;/work/source_code/testingfiles/aes192.c:43: }
	pop	ix
	C$aes192.c$43$2_0$40	= .
	.globl	C$aes192.c$43$2_0$40
	XFaes192$SubBytes$0$0	= .
	.globl	XFaes192$SubBytes$0$0
	ret
	Faes192$ShiftRows$0$0	= .
	.globl	Faes192$ShiftRows$0$0
	C$aes192.c$45$2_0$42	= .
	.globl	C$aes192.c$45$2_0$42
;/work/source_code/testingfiles/aes192.c:45: static void ShiftRows(uint8_t *s) {
;	---------------------------------
; Function ShiftRows
; ---------------------------------
_ShiftRows:
	call	___sdcc_enter_ix
	ld	hl, #-16
	add	hl, sp
	ld	sp, hl
	C$aes192.c$47$1_0$42	= .
	.globl	C$aes192.c$47$1_0$42
;/work/source_code/testingfiles/aes192.c:47: memcpy(t, s, 16);
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
	C$aes192.c$49$1_0$42	= .
	.globl	C$aes192.c$49$1_0$42
;/work/source_code/testingfiles/aes192.c:49: s[1]  = t[5];  s[5]  = t[9];  s[9]  = t[13]; s[13] = t[1];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x05
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0009
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x09
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000d
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0d
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$50$1_0$42	= .
	.globl	C$aes192.c$50$1_0$42
;/work/source_code/testingfiles/aes192.c:50: s[2]  = t[10]; s[10] = t[2];  s[6]  = t[14]; s[14] = t[6];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	inc	de
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000a
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0a
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x06
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000e
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0e
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0006
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$51$1_0$42	= .
	.globl	C$aes192.c$51$1_0$42
;/work/source_code/testingfiles/aes192.c:51: s[3]  = t[15]; s[7]  = t[3];  s[11] = t[7];  s[15] = t[11];
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	inc	de
	inc	de
	inc	de
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x000f
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x07
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0b
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	ld	bc, #0x0007
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	a, 4 (ix)
	add	a, #0x0f
	ld	e, a
	ld	a, 5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	ld	bc, #0x000b
	add	hl, bc
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$52$1_0$42	= .
	.globl	C$aes192.c$52$1_0$42
;/work/source_code/testingfiles/aes192.c:52: }
	ld	sp, ix
	pop	ix
	C$aes192.c$52$1_0$42	= .
	.globl	C$aes192.c$52$1_0$42
	XFaes192$ShiftRows$0$0	= .
	.globl	XFaes192$ShiftRows$0$0
	ret
	Faes192$MixColumns$0$0	= .
	.globl	Faes192$MixColumns$0$0
	C$aes192.c$54$1_0$45	= .
	.globl	C$aes192.c$54$1_0$45
;/work/source_code/testingfiles/aes192.c:54: static void MixColumns(uint8_t *s) {
;	---------------------------------
; Function MixColumns
; ---------------------------------
_MixColumns:
	call	___sdcc_enter_ix
	ld	hl, #-11
	add	hl, sp
	ld	sp, hl
	C$aes192.c$55$2_0$45	= .
	.globl	C$aes192.c$55$2_0$45
;/work/source_code/testingfiles/aes192.c:55: for(int i=0;i<4;i++){
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
	C$aes192.c$56$3_0$46	= .
	.globl	C$aes192.c$56$3_0$46
;/work/source_code/testingfiles/aes192.c:56: uint8_t a = s[4*i+0], b = s[4*i+1], c = s[4*i+2], d = s[4*i+3];
	ld	e, c
	ld	d, b
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, 4 (ix)
	add	a, e
	ld	-11 (ix), a
	ld	a, 5 (ix)
	adc	a, d
	ld	-10 (ix), a
	pop	hl
	push	hl
	ld	a, (hl)
	ld	-9 (ix), a
	ld	hl, #0x0001
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 4 (ix)
	ld	-8 (ix), a
	ld	a, -1 (ix)
	adc	a, 5 (ix)
	ld	-7 (ix), a
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	a, (hl)
	ld	-6 (ix), a
	ld	hl, #0x0002
	add	hl, de
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 4 (ix)
	ld	-5 (ix), a
	ld	a, -1 (ix)
	adc	a, 5 (ix)
	ld	-4 (ix), a
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	a, (hl)
	ld	-3 (ix), a
	inc	de
	inc	de
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-1 (ix), a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	e, (hl)
	C$aes192.c$57$3_0$46	= .
	.globl	C$aes192.c$57$3_0$46
;/work/source_code/testingfiles/aes192.c:57: s[4*i+0] = xt(a) ^ xt(b) ^ b ^ c ^ d;
	push	bc
	push	de
	ld	a, -9 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	pop	de
	pop	bc
	push	hl
	push	bc
	push	de
	ld	a, -6 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	pop	hl
	xor	a, l
	xor	a, -6 (ix)
	xor	a, -3 (ix)
	xor	a, e
	pop	hl
	push	hl
	ld	(hl), a
	C$aes192.c$58$3_0$46	= .
	.globl	C$aes192.c$58$3_0$46
;/work/source_code/testingfiles/aes192.c:58: s[4*i+1] = a ^ xt(b) ^ xt(c) ^ c ^ d;
	push	bc
	push	de
	ld	a, -6 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -9 (ix)
	ld	d, a
	push	bc
	push	de
	ld	a, -3 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	xor	a, -3 (ix)
	xor	a, e
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
	C$aes192.c$59$3_0$46	= .
	.globl	C$aes192.c$59$3_0$46
;/work/source_code/testingfiles/aes192.c:59: s[4*i+2] = a ^ b ^ xt(c) ^ xt(d) ^ d;
	ld	a, -9 (ix)
	xor	a, -6 (ix)
	ld	d, a
	push	bc
	push	de
	ld	a, -3 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	ld	d, a
	push	bc
	push	de
	ld	a, e
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, d
	xor	a, e
	ld	l, -5 (ix)
	ld	h, -4 (ix)
	ld	(hl), a
	C$aes192.c$60$3_0$46	= .
	.globl	C$aes192.c$60$3_0$46
;/work/source_code/testingfiles/aes192.c:60: s[4*i+3] = xt(a) ^ a ^ b ^ c ^ xt(d);
	push	bc
	push	de
	ld	a, -9 (ix)
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	de
	pop	bc
	xor	a, -9 (ix)
	xor	a, -6 (ix)
	xor	a, -3 (ix)
	ld	l, a
	push	hl
	push	bc
	ld	a, e
	push	af
	inc	sp
	call	_xt
	inc	sp
	ld	a, l
	pop	bc
	pop	hl
	xor	a, l
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$55$2_0$45	= .
	.globl	C$aes192.c$55$2_0$45
;/work/source_code/testingfiles/aes192.c:55: for(int i=0;i<4;i++){
	inc	bc
	jp	00103$
00105$:
	C$aes192.c$62$2_0$45	= .
	.globl	C$aes192.c$62$2_0$45
;/work/source_code/testingfiles/aes192.c:62: }
	ld	sp, ix
	pop	ix
	C$aes192.c$62$2_0$45	= .
	.globl	C$aes192.c$62$2_0$45
	XFaes192$MixColumns$0$0	= .
	.globl	XFaes192$MixColumns$0$0
	ret
	Faes192$AddRoundKey$0$0	= .
	.globl	Faes192$AddRoundKey$0$0
	C$aes192.c$64$2_0$49	= .
	.globl	C$aes192.c$64$2_0$49
;/work/source_code/testingfiles/aes192.c:64: static void AddRoundKey(uint8_t *s, uint8_t rk[16]) {
;	---------------------------------
; Function AddRoundKey
; ---------------------------------
_AddRoundKey:
	call	___sdcc_enter_ix
	dec	sp
	C$aes192.c$65$2_0$49	= .
	.globl	C$aes192.c$65$2_0$49
;/work/source_code/testingfiles/aes192.c:65: for(int i=0;i<16;i++) s[i] ^= rk[i];
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
	ld	-1 (ix), a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, bc
	ld	a, (hl)
	xor	a, -1 (ix)
	ld	(de), a
	inc	bc
	jr	00103$
00105$:
	C$aes192.c$66$2_0$49	= .
	.globl	C$aes192.c$66$2_0$49
;/work/source_code/testingfiles/aes192.c:66: }
	inc	sp
	pop	ix
	C$aes192.c$66$2_0$49	= .
	.globl	C$aes192.c$66$2_0$49
	XFaes192$AddRoundKey$0$0	= .
	.globl	XFaes192$AddRoundKey$0$0
	ret
	Faes192$KeyExpansion$0$0	= .
	.globl	Faes192$KeyExpansion$0$0
	C$aes192.c$68$2_0$51	= .
	.globl	C$aes192.c$68$2_0$51
;/work/source_code/testingfiles/aes192.c:68: static void KeyExpansion(uint8_t key[24], uint8_t roundKeys[13][16]) {
;	---------------------------------
; Function KeyExpansion
; ---------------------------------
_KeyExpansion:
	call	___sdcc_enter_ix
	ld	hl, #-226
	add	hl, sp
	ld	sp, hl
	C$aes192.c$72$1_0$51	= .
	.globl	C$aes192.c$72$1_0$51
;/work/source_code/testingfiles/aes192.c:72: memcpy(expanded, key, 24);
	ld	hl, #4
	add	hl, sp
	ld	-14 (ix), l
	ld	-13 (ix), h
	ex	de,hl
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	ld	bc, #0x0018
	ldir
	C$aes192.c$74$2_0$52	= .
	.globl	C$aes192.c$74$2_0$52
;/work/source_code/testingfiles/aes192.c:74: int bytesUsed = 24;
	ld	-12 (ix), #0x18
	xor	a, a
	ld	-11 (ix), a
	C$aes192.c$77$3_1$54	= .
	.globl	C$aes192.c$77$3_1$54
;/work/source_code/testingfiles/aes192.c:77: while (bytesUsed < 208) {
	ld	hl, #0
	add	hl, sp
	ld	-10 (ix), l
	ld	-9 (ix), h
	ld	a, -10 (ix)
	ld	-8 (ix), a
	ld	a, -9 (ix)
	ld	-7 (ix), a
	ld	-6 (ix), #0x01
	xor	a, a
	ld	-5 (ix), a
00105$:
	ld	a, -12 (ix)
	sub	a, #0xd0
	ld	a, -11 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00107$
	C$aes192.c$78$3_1$54	= .
	.globl	C$aes192.c$78$3_1$54
;/work/source_code/testingfiles/aes192.c:78: for(int i=0;i<4;i++)
	ld	a, -12 (ix)
	add	a, #0xfc
	ld	-4 (ix), a
	ld	a, -11 (ix)
	adc	a, #0xff
	ld	-3 (ix), a
	ld	bc, #0x0000
00110$:
	ld	a, c
	sub	a, #0x04
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$aes192.c$79$3_1$54	= .
	.globl	C$aes192.c$79$3_1$54
;/work/source_code/testingfiles/aes192.c:79: temp[i] = expanded[bytesUsed - 4 + i];
	ld	a, -10 (ix)
	add	a, c
	ld	-2 (ix), a
	ld	a, -9 (ix)
	adc	a, b
	ld	-1 (ix), a
	ld	a, -4 (ix)
	add	a, c
	ld	e, a
	ld	a, -3 (ix)
	adc	a, b
	ld	d, a
	ld	a, e
	add	a, -14 (ix)
	ld	e, a
	ld	a, d
	adc	a, -13 (ix)
	ld	d, a
	ld	a, (de)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	C$aes192.c$78$3_1$54	= .
	.globl	C$aes192.c$78$3_1$54
;/work/source_code/testingfiles/aes192.c:78: for(int i=0;i<4;i++)
	inc	bc
	jr	00110$
00101$:
	C$aes192.c$81$2_1$51	= .
	.globl	C$aes192.c$81$2_1$51
;/work/source_code/testingfiles/aes192.c:81: if (bytesUsed % 24 == 0) {
	ld	hl, #0x0018
	push	hl
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	push	hl
	call	__modsint
	pop	af
	pop	af
	ld	c, l
	ld	a, h
	or	a, c
	jr	NZ,00126$
	C$aes192.c$82$3_1$55	= .
	.globl	C$aes192.c$82$3_1$55
;/work/source_code/testingfiles/aes192.c:82: uint8_t t = temp[0];
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	a, (hl)
	ld	-2 (ix), a
	C$aes192.c$83$3_1$55	= .
	.globl	C$aes192.c$83$3_1$55
;/work/source_code/testingfiles/aes192.c:83: temp[0] = SBOX[temp[1]];
	ld	c, -10 (ix)
	ld	b, -9 (ix)
	inc	bc
	ld	a, (bc)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	-1 (ix), a
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	a, -1 (ix)
	ld	(hl), a
	C$aes192.c$84$3_1$55	= .
	.globl	C$aes192.c$84$3_1$55
;/work/source_code/testingfiles/aes192.c:84: temp[1] = SBOX[temp[2]];
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	inc	de
	inc	de
	ld	a, (de)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(bc), a
	C$aes192.c$85$3_1$55	= .
	.globl	C$aes192.c$85$3_1$55
;/work/source_code/testingfiles/aes192.c:85: temp[2] = SBOX[temp[3]];
	ld	c, -10 (ix)
	ld	b, -9 (ix)
	inc	bc
	inc	bc
	inc	bc
	ld	a, (bc)
	add	a, #<(_SBOX)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_SBOX)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	C$aes192.c$86$3_1$55	= .
	.globl	C$aes192.c$86$3_1$55
;/work/source_code/testingfiles/aes192.c:86: temp[3] = SBOX[t];
	ld	a, #<(_SBOX)
	add	a, -2 (ix)
	ld	e, a
	ld	a, #>(_SBOX)
	adc	a, #0x00
	ld	d, a
	ld	a, (de)
	ld	(bc), a
	C$aes192.c$87$3_1$55	= .
	.globl	C$aes192.c$87$3_1$55
;/work/source_code/testingfiles/aes192.c:87: temp[0] ^= RCON[rconIter++];
	ld	a, #<(_RCON)
	add	a, -6 (ix)
	ld	c, a
	ld	a, #>(_RCON)
	adc	a, -5 (ix)
	ld	b, a
	inc	-6 (ix)
	jr	NZ,00168$
	inc	-5 (ix)
00168$:
	ld	a, (bc)
	xor	a, -1 (ix)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	C$aes192.c$90$2_1$51	= .
	.globl	C$aes192.c$90$2_1$51
;/work/source_code/testingfiles/aes192.c:90: for(int i=0;i<4;i++)
00126$:
	ld	a, -12 (ix)
	ld	-4 (ix), a
	ld	a, -11 (ix)
	ld	-3 (ix), a
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00113$:
	ld	a, -2 (ix)
	sub	a, #0x04
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jp	NC, 00105$
	C$aes192.c$91$3_1$56	= .
	.globl	C$aes192.c$91$3_1$56
;/work/source_code/testingfiles/aes192.c:91: expanded[bytesUsed++] = expanded[bytesUsed - 24] ^ temp[i];
	ld	c, -4 (ix)
	ld	b, -3 (ix)
	inc	-4 (ix)
	jr	NZ,00169$
	inc	-3 (ix)
00169$:
	ld	a, -4 (ix)
	ld	-12 (ix), a
	ld	a, -3 (ix)
	ld	-11 (ix), a
	ld	a, -14 (ix)
	add	a, c
	ld	c, a
	ld	a, -13 (ix)
	adc	a, b
	ld	b, a
	ld	a, -4 (ix)
	add	a, #0xe8
	ld	e, a
	ld	a, -3 (ix)
	adc	a, #0xff
	ld	d, a
	ld	a, -14 (ix)
	add	a, e
	ld	e, a
	ld	a, -13 (ix)
	adc	a, d
	ld	d, a
	ld	a, (de)
	ld	e, a
	ld	a, -8 (ix)
	add	a, -2 (ix)
	ld	d, a
	ld	a, -7 (ix)
	adc	a, -1 (ix)
	ld	l, d
	ld	h, a
	ld	a, (hl)
	xor	a, e
	ld	(bc), a
	C$aes192.c$90$3_1$56	= .
	.globl	C$aes192.c$90$3_1$56
;/work/source_code/testingfiles/aes192.c:90: for(int i=0;i<4;i++)
	inc	-2 (ix)
	jr	NZ,00113$
	inc	-1 (ix)
	jr	00113$
00107$:
	C$aes192.c$94$2_1$51	= .
	.globl	C$aes192.c$94$2_1$51
;/work/source_code/testingfiles/aes192.c:94: for(int r=0;r<Nr+1;r++)
	xor	a, a
	ld	-2 (ix), a
	ld	-1 (ix), a
00116$:
	ld	a, -2 (ix)
	sub	a, #0x0d
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00118$
	C$aes192.c$95$2_1$57	= .
	.globl	C$aes192.c$95$2_1$57
;/work/source_code/testingfiles/aes192.c:95: memcpy(roundKeys[r], expanded + (r*16), 16);
	ld	c, -2 (ix)
	ld	b, -1 (ix)
	sla	c
	rl	b
	sla	c
	rl	b
	sla	c
	rl	b
	sla	c
	rl	b
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, bc
	ex	de,hl
	ld	a, -14 (ix)
	add	a, c
	ld	c, a
	ld	a, -13 (ix)
	adc	a, b
	ld	l, c
	ld	h, a
	ld	bc, #0x0010
	ldir
	C$aes192.c$94$2_1$57	= .
	.globl	C$aes192.c$94$2_1$57
;/work/source_code/testingfiles/aes192.c:94: for(int r=0;r<Nr+1;r++)
	inc	-2 (ix)
	jr	NZ,00116$
	inc	-1 (ix)
	jr	00116$
00118$:
	C$aes192.c$96$2_1$51	= .
	.globl	C$aes192.c$96$2_1$51
;/work/source_code/testingfiles/aes192.c:96: }
	ld	sp, ix
	pop	ix
	C$aes192.c$96$2_1$51	= .
	.globl	C$aes192.c$96$2_1$51
	XFaes192$KeyExpansion$0$0	= .
	.globl	XFaes192$KeyExpansion$0$0
	ret
	G$AES192_Encrypt$0$0	= .
	.globl	G$AES192_Encrypt$0$0
	C$aes192.c$98$2_1$59	= .
	.globl	C$aes192.c$98$2_1$59
;/work/source_code/testingfiles/aes192.c:98: void AES192_Encrypt(uint8_t *in, uint8_t *out, uint8_t key[24]) {
;	---------------------------------
; Function AES192_Encrypt
; ---------------------------------
_AES192_Encrypt::
	call	___sdcc_enter_ix
	ld	hl, #-236
	add	hl, sp
	ld	sp, hl
	C$aes192.c$102$1_0$59	= .
	.globl	C$aes192.c$102$1_0$59
;/work/source_code/testingfiles/aes192.c:102: memcpy(state, in, 16);
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
	C$aes192.c$103$1_0$59	= .
	.globl	C$aes192.c$103$1_0$59
;/work/source_code/testingfiles/aes192.c:103: KeyExpansion(key, rk);
	ld	hl, #16
	add	hl, sp
	push	bc
	push	hl
	ld	l, 8 (ix)
	ld	h, 9 (ix)
	push	hl
	call	_KeyExpansion
	pop	af
	pop	af
	pop	bc
	C$aes192.c$105$1_0$59	= .
	.globl	C$aes192.c$105$1_0$59
;/work/source_code/testingfiles/aes192.c:105: AddRoundKey(state, rk[0]);
	ld	hl, #16
	add	hl, sp
	ld	e, c
	ld	d, b
	push	bc
	push	hl
	push	de
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes192.c$107$3_0$61	= .
	.globl	C$aes192.c$107$3_0$61
;/work/source_code/testingfiles/aes192.c:107: for(int round=1; round<Nr; round++){
	ld	-12 (ix), c
	ld	-11 (ix), b
	ld	-10 (ix), c
	ld	-9 (ix), b
	ld	-8 (ix), c
	ld	-7 (ix), b
	ld	hl, #16
	add	hl, sp
	ld	-6 (ix), l
	ld	-5 (ix), h
	ld	-4 (ix), c
	ld	-3 (ix), b
	ld	-2 (ix), #0x01
	xor	a, a
	ld	-1 (ix), a
00103$:
	ld	a, -2 (ix)
	sub	a, #0x0c
	ld	a, -1 (ix)
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	C$aes192.c$108$3_0$61	= .
	.globl	C$aes192.c$108$3_0$61
;/work/source_code/testingfiles/aes192.c:108: SubBytes(state);
	ld	e, -12 (ix)
	ld	d, -11 (ix)
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes192.c$109$3_0$61	= .
	.globl	C$aes192.c$109$3_0$61
;/work/source_code/testingfiles/aes192.c:109: ShiftRows(state);
	ld	e, -10 (ix)
	ld	d, -9 (ix)
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes192.c$110$3_0$61	= .
	.globl	C$aes192.c$110$3_0$61
;/work/source_code/testingfiles/aes192.c:110: MixColumns(state);
	ld	e, -8 (ix)
	ld	d, -7 (ix)
	push	bc
	push	de
	call	_MixColumns
	pop	af
	pop	bc
	C$aes192.c$111$3_0$61	= .
	.globl	C$aes192.c$111$3_0$61
;/work/source_code/testingfiles/aes192.c:111: AddRoundKey(state, rk[round]);
	ld	e, -2 (ix)
	ld	d, -1 (ix)
	sla	e
	rl	d
	sla	e
	rl	d
	sla	e
	rl	d
	sla	e
	rl	d
	ld	a, e
	add	a, -6 (ix)
	ld	e, a
	ld	a, d
	adc	a, -5 (ix)
	ld	d, a
	ld	l, -4 (ix)
	ld	h, -3 (ix)
	push	bc
	push	de
	push	hl
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes192.c$107$2_0$60	= .
	.globl	C$aes192.c$107$2_0$60
;/work/source_code/testingfiles/aes192.c:107: for(int round=1; round<Nr; round++){
	inc	-2 (ix)
	jr	NZ,00103$
	inc	-1 (ix)
	jr	00103$
00101$:
	C$aes192.c$114$1_0$59	= .
	.globl	C$aes192.c$114$1_0$59
;/work/source_code/testingfiles/aes192.c:114: SubBytes(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_SubBytes
	pop	af
	pop	bc
	C$aes192.c$115$1_0$59	= .
	.globl	C$aes192.c$115$1_0$59
;/work/source_code/testingfiles/aes192.c:115: ShiftRows(state);
	ld	e, c
	ld	d, b
	push	bc
	push	de
	call	_ShiftRows
	pop	af
	pop	bc
	C$aes192.c$116$1_0$59	= .
	.globl	C$aes192.c$116$1_0$59
;/work/source_code/testingfiles/aes192.c:116: AddRoundKey(state, rk[Nr]);
	ld	a, -6 (ix)
	add	a, #0xc0
	ld	e, a
	ld	a, -5 (ix)
	adc	a, #0x00
	ld	d, a
	ld	l, c
	ld	h, b
	push	bc
	push	de
	push	hl
	call	_AddRoundKey
	pop	af
	pop	af
	pop	bc
	C$aes192.c$118$1_0$59	= .
	.globl	C$aes192.c$118$1_0$59
;/work/source_code/testingfiles/aes192.c:118: memcpy(out, state, 16);
	ld	e, 6 (ix)
	ld	d, 7 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
	C$aes192.c$119$1_0$59	= .
	.globl	C$aes192.c$119$1_0$59
;/work/source_code/testingfiles/aes192.c:119: }
	ld	sp, ix
	pop	ix
	C$aes192.c$119$1_0$59	= .
	.globl	C$aes192.c$119$1_0$59
	XG$AES192_Encrypt$0$0	= .
	.globl	XG$AES192_Encrypt$0$0
	ret
	G$main$0$0	= .
	.globl	G$main$0$0
	C$aes192.c$121$1_0$62	= .
	.globl	C$aes192.c$121$1_0$62
;/work/source_code/testingfiles/aes192.c:121: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	call	___sdcc_enter_ix
	ld	hl, #-58
	add	hl, sp
	ld	sp, hl
	C$aes192.c$122$2_0$62	= .
	.globl	C$aes192.c$122$2_0$62
;/work/source_code/testingfiles/aes192.c:122: uint8_t key[24] = {
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	a, #0x8e
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x73
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0xb0
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xf7
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0xda
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x0e
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x64
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0xc8
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x10
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0xf3
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x2b
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x80
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x90
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x79
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0xe5
	ld	hl, #0x0010
	add	hl, de
	ld	(hl), #0x62
	ld	hl, #0x0011
	add	hl, de
	ld	(hl), #0xf8
	ld	hl, #0x0012
	add	hl, de
	ld	(hl), #0xea
	ld	hl, #0x0013
	add	hl, de
	ld	(hl), #0xd2
	ld	hl, #0x0014
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0015
	add	hl, de
	ld	(hl), #0x2c
	ld	hl, #0x0016
	add	hl, de
	ld	(hl), #0x6b
	ld	hl, #0x0017
	add	hl, de
	ld	(hl), #0x7b
	C$aes192.c$128$2_0$62	= .
	.globl	C$aes192.c$128$2_0$62
;/work/source_code/testingfiles/aes192.c:128: uint8_t plaintext[16] = {
	ld	hl, #24
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, #0x6b
	ld	(bc), a
	ld	l, c
	ld	h, b
	inc	hl
	ld	(hl), #0xc1
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), #0xbe
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xe2
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x2e
	ld	hl, #0x0005
	add	hl, bc
	ld	(hl), #0x40
	ld	hl, #0x0006
	add	hl, bc
	ld	(hl), #0x9f
	ld	hl, #0x0007
	add	hl, bc
	ld	(hl), #0x96
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0xe9
	ld	hl, #0x0009
	add	hl, bc
	ld	(hl), #0x3d
	ld	hl, #0x000a
	add	hl, bc
	ld	(hl), #0x7e
	ld	hl, #0x000b
	add	hl, bc
	ld	(hl), #0x11
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0x73
	ld	hl, #0x000d
	add	hl, bc
	ld	(hl), #0x93
	ld	hl, #0x000e
	add	hl, bc
	ld	(hl), #0x17
	ld	hl, #0x000f
	add	hl, bc
	ld	(hl), #0x2a
	C$aes192.c$135$1_0$62	= .
	.globl	C$aes192.c$135$1_0$62
;/work/source_code/testingfiles/aes192.c:135: AES192_Encrypt(plaintext, ciphertext, key);
	ld	hl, #40
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	push	de
	push	hl
	push	bc
	call	_AES192_Encrypt
	pop	af
	pop	af
	C$aes192.c$137$1_0$62	= .
	.globl	C$aes192.c$137$1_0$62
;/work/source_code/testingfiles/aes192.c:137: printf("AES-192 Encryption Output:\n");
	ld	hl, #___str_1
	ex	(sp),hl
	call	_puts
	pop	af
	C$aes192.c$138$2_0$63	= .
	.globl	C$aes192.c$138$2_0$63
;/work/source_code/testingfiles/aes192.c:138: for(int i=0;i<16;i++)
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
	C$aes192.c$139$2_0$63	= .
	.globl	C$aes192.c$139$2_0$63
;/work/source_code/testingfiles/aes192.c:139: printf("%02x ", ciphertext[i]);
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	add	hl, bc
	ld	e, (hl)
	ld	d, #0x00
	push	bc
	push	de
	ld	hl, #___str_2
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	bc
	C$aes192.c$138$2_0$63	= .
	.globl	C$aes192.c$138$2_0$63
;/work/source_code/testingfiles/aes192.c:138: for(int i=0;i<16;i++)
	inc	bc
	jr	00103$
00101$:
	C$aes192.c$140$1_0$62	= .
	.globl	C$aes192.c$140$1_0$62
;/work/source_code/testingfiles/aes192.c:140: printf("\n");
	ld	hl, #___str_4
	push	hl
	call	_puts
	pop	af
	C$aes192.c$142$1_0$62	= .
	.globl	C$aes192.c$142$1_0$62
;/work/source_code/testingfiles/aes192.c:142: return 0;
	ld	hl, #0x0000
	C$aes192.c$143$1_0$62	= .
	.globl	C$aes192.c$143$1_0$62
;/work/source_code/testingfiles/aes192.c:143: }
	ld	sp, ix
	pop	ix
	C$aes192.c$143$1_0$62	= .
	.globl	C$aes192.c$143$1_0$62
	XG$main$0$0	= .
	.globl	XG$main$0$0
	ret
Faes192$__str_1$0_0$0 == .
___str_1:
	.ascii "AES-192 Encryption Output:"
	.db 0x00
Faes192$__str_2$0_0$0 == .
___str_2:
	.ascii "%02x "
	.db 0x00
Faes192$__str_4$0_0$0 == .
___str_4:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
