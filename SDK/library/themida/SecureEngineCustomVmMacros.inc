; ****************************************************************************
; Module: SecureEngineCustomVmMacros.inc
; Description: Another way to link with the SecureEngine SDK via an ASM module
;
; Author/s: Oreans Technologies 
; (c) 2023 Oreans Technologies
;
; --- File generated automatically from Oreans VM Generator (16/9/2023) ---
; ****************************************************************************


IFDEF RAX

ELSE

.586
.model flat,stdcall
option casemap:none

ENDIF


; ****************************************************************************
;                                 Constants
; ****************************************************************************

.CONST


; ****************************************************************************
;                               Data Segment
; ****************************************************************************

.DATA


; ****************************************************************************
;                               Code Segment
; ****************************************************************************

.CODE

IFDEF RAX

; ****************************************************************************
; VM_TIGER_WHITE definition
; ****************************************************************************

VM_TIGER_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 103
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_WHITE_START_ASM64 ENDP

VM_TIGER_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 503
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_TIGER_RED definition
; ****************************************************************************

VM_TIGER_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 104
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_RED_START_ASM64 ENDP

VM_TIGER_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 504
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_TIGER_BLACK definition
; ****************************************************************************

VM_TIGER_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 105
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_BLACK_START_ASM64 ENDP

VM_TIGER_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 505
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_TIGER_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_FISH_WHITE definition
; ****************************************************************************

VM_FISH_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 107
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_WHITE_START_ASM64 ENDP

VM_FISH_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 507
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_FISH_RED definition
; ****************************************************************************

VM_FISH_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 109
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_RED_START_ASM64 ENDP

VM_FISH_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 509
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_FISH_BLACK definition
; ****************************************************************************

VM_FISH_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 111
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_BLACK_START_ASM64 ENDP

VM_FISH_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 511
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FISH_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_PUMA_WHITE definition
; ****************************************************************************

VM_PUMA_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 113
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_WHITE_START_ASM64 ENDP

VM_PUMA_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 513
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_PUMA_RED definition
; ****************************************************************************

VM_PUMA_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 115
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_RED_START_ASM64 ENDP

VM_PUMA_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 515
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_PUMA_BLACK definition
; ****************************************************************************

VM_PUMA_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 117
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_BLACK_START_ASM64 ENDP

VM_PUMA_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 517
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_PUMA_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_SHARK_WHITE definition
; ****************************************************************************

VM_SHARK_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 119
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_WHITE_START_ASM64 ENDP

VM_SHARK_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 519
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_SHARK_RED definition
; ****************************************************************************

VM_SHARK_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 121
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_RED_START_ASM64 ENDP

VM_SHARK_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 521
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_SHARK_BLACK definition
; ****************************************************************************

VM_SHARK_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 123
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_BLACK_START_ASM64 ENDP

VM_SHARK_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 523
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_SHARK_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_DOLPHIN_WHITE definition
; ****************************************************************************

VM_DOLPHIN_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 135
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_WHITE_START_ASM64 ENDP

VM_DOLPHIN_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 535
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_DOLPHIN_RED definition
; ****************************************************************************

VM_DOLPHIN_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 137
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_RED_START_ASM64 ENDP

VM_DOLPHIN_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 537
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_DOLPHIN_BLACK definition
; ****************************************************************************

VM_DOLPHIN_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 139
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_BLACK_START_ASM64 ENDP

VM_DOLPHIN_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 539
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_DOLPHIN_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_EAGLE_WHITE definition
; ****************************************************************************

VM_EAGLE_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 147
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_WHITE_START_ASM64 ENDP

VM_EAGLE_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 547
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_EAGLE_RED definition
; ****************************************************************************

VM_EAGLE_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 149
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_RED_START_ASM64 ENDP

VM_EAGLE_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 549
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_EAGLE_BLACK definition
; ****************************************************************************

VM_EAGLE_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 151
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_BLACK_START_ASM64 ENDP

VM_EAGLE_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 551
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_EAGLE_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_LION_WHITE definition
; ****************************************************************************

VM_LION_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 161
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_WHITE_START_ASM64 ENDP

VM_LION_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 561
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_LION_RED definition
; ****************************************************************************

VM_LION_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 163
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_RED_START_ASM64 ENDP

VM_LION_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 563
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_LION_BLACK definition
; ****************************************************************************

VM_LION_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 165
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_BLACK_START_ASM64 ENDP

VM_LION_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 565
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_LION_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_COBRA_WHITE definition
; ****************************************************************************

VM_COBRA_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 167
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_WHITE_START_ASM64 ENDP

VM_COBRA_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 567
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_COBRA_RED definition
; ****************************************************************************

VM_COBRA_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 169
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_RED_START_ASM64 ENDP

VM_COBRA_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 569
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_COBRA_BLACK definition
; ****************************************************************************

VM_COBRA_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 171
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_BLACK_START_ASM64 ENDP

VM_COBRA_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 571
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_COBRA_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_WOLF_WHITE definition
; ****************************************************************************

VM_WOLF_WHITE_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 173
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_WHITE_START_ASM64 ENDP

VM_WOLF_WHITE_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 573
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_WHITE_END_ASM64 ENDP


; ****************************************************************************
; VM_WOLF_RED definition
; ****************************************************************************

VM_WOLF_RED_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 175
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_RED_START_ASM64 ENDP

VM_WOLF_RED_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 575
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_RED_END_ASM64 ENDP


; ****************************************************************************
; VM_WOLF_BLACK definition
; ****************************************************************************

VM_WOLF_BLACK_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 177
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_BLACK_START_ASM64 ENDP

VM_WOLF_BLACK_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 577
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_WOLF_BLACK_END_ASM64 ENDP


; ****************************************************************************
; VM_MUTATE_ONLY definition
; ****************************************************************************

VM_MUTATE_ONLY_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 16
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_MUTATE_ONLY_START_ASM64 ENDP

VM_MUTATE_ONLY_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 17
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_MUTATE_ONLY_END_ASM64 ENDP


; ****************************************************************************
; VM_FALCON_TINY definition
; ****************************************************************************

VM_FALCON_TINY_START_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 218
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FALCON_TINY_START_ASM64 ENDP

VM_FALCON_TINY_END_ASM64 PROC

    push    rax
    push    rbx
    push    rcx

    mov     eax, 'TMWL'
    mov     ebx, 618
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     rcx
    pop     rbx
    pop     rax
    ret

VM_FALCON_TINY_END_ASM64 ENDP

ELSE

; ****************************************************************************
; VM_TIGER_WHITE definition
; ****************************************************************************

VM_TIGER_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 100
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_WHITE_START_ASM32 ENDP

VM_TIGER_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 500
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_TIGER_RED definition
; ****************************************************************************

VM_TIGER_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 101
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_RED_START_ASM32 ENDP

VM_TIGER_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 501
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_TIGER_BLACK definition
; ****************************************************************************

VM_TIGER_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 102
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_BLACK_START_ASM32 ENDP

VM_TIGER_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 502
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_TIGER_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_FISH_WHITE definition
; ****************************************************************************

VM_FISH_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 106
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_WHITE_START_ASM32 ENDP

VM_FISH_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 506
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_FISH_RED definition
; ****************************************************************************

VM_FISH_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 108
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_RED_START_ASM32 ENDP

VM_FISH_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 508
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_FISH_BLACK definition
; ****************************************************************************

VM_FISH_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 110
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_BLACK_START_ASM32 ENDP

VM_FISH_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 510
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FISH_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_PUMA_WHITE definition
; ****************************************************************************

VM_PUMA_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 112
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_WHITE_START_ASM32 ENDP

VM_PUMA_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 512
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_PUMA_RED definition
; ****************************************************************************

VM_PUMA_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 114
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_RED_START_ASM32 ENDP

VM_PUMA_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 514
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_PUMA_BLACK definition
; ****************************************************************************

VM_PUMA_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 116
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_BLACK_START_ASM32 ENDP

VM_PUMA_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 516
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_PUMA_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_SHARK_WHITE definition
; ****************************************************************************

VM_SHARK_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 118
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_WHITE_START_ASM32 ENDP

VM_SHARK_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 518
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_SHARK_RED definition
; ****************************************************************************

VM_SHARK_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 120
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_RED_START_ASM32 ENDP

VM_SHARK_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 520
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_SHARK_BLACK definition
; ****************************************************************************

VM_SHARK_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 122
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_BLACK_START_ASM32 ENDP

VM_SHARK_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 522
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_SHARK_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_DOLPHIN_WHITE definition
; ****************************************************************************

VM_DOLPHIN_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 134
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_WHITE_START_ASM32 ENDP

VM_DOLPHIN_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 534
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_DOLPHIN_RED definition
; ****************************************************************************

VM_DOLPHIN_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 136
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_RED_START_ASM32 ENDP

VM_DOLPHIN_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 536
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_DOLPHIN_BLACK definition
; ****************************************************************************

VM_DOLPHIN_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 138
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_BLACK_START_ASM32 ENDP

VM_DOLPHIN_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 538
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_DOLPHIN_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_EAGLE_WHITE definition
; ****************************************************************************

VM_EAGLE_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 146
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_WHITE_START_ASM32 ENDP

VM_EAGLE_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 546
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_EAGLE_RED definition
; ****************************************************************************

VM_EAGLE_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 148
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_RED_START_ASM32 ENDP

VM_EAGLE_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 548
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_EAGLE_BLACK definition
; ****************************************************************************

VM_EAGLE_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 150
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_BLACK_START_ASM32 ENDP

VM_EAGLE_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 550
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_EAGLE_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_LION_WHITE definition
; ****************************************************************************

VM_LION_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 160
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_WHITE_START_ASM32 ENDP

VM_LION_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 560
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_LION_RED definition
; ****************************************************************************

VM_LION_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 162
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_RED_START_ASM32 ENDP

VM_LION_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 562
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_LION_BLACK definition
; ****************************************************************************

VM_LION_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 164
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_BLACK_START_ASM32 ENDP

VM_LION_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 564
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_LION_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_COBRA_WHITE definition
; ****************************************************************************

VM_COBRA_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 166
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_WHITE_START_ASM32 ENDP

VM_COBRA_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 566
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_COBRA_RED definition
; ****************************************************************************

VM_COBRA_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 168
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_RED_START_ASM32 ENDP

VM_COBRA_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 568
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_COBRA_BLACK definition
; ****************************************************************************

VM_COBRA_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 170
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_BLACK_START_ASM32 ENDP

VM_COBRA_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 570
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_COBRA_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_WOLF_WHITE definition
; ****************************************************************************

VM_WOLF_WHITE_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 172
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_WHITE_START_ASM32 ENDP

VM_WOLF_WHITE_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 572
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_WHITE_END_ASM32 ENDP


; ****************************************************************************
; VM_WOLF_RED definition
; ****************************************************************************

VM_WOLF_RED_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 174
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_RED_START_ASM32 ENDP

VM_WOLF_RED_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 574
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_RED_END_ASM32 ENDP


; ****************************************************************************
; VM_WOLF_BLACK definition
; ****************************************************************************

VM_WOLF_BLACK_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 176
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_BLACK_START_ASM32 ENDP

VM_WOLF_BLACK_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 576
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_WOLF_BLACK_END_ASM32 ENDP


; ****************************************************************************
; VM_MUTATE_ONLY definition
; ****************************************************************************

VM_MUTATE_ONLY_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 16
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_MUTATE_ONLY_START_ASM32 ENDP

VM_MUTATE_ONLY_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 17
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_MUTATE_ONLY_END_ASM32 ENDP


; ****************************************************************************
; VM_FALCON_TINY definition
; ****************************************************************************

VM_FALCON_TINY_START_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 217
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FALCON_TINY_START_ASM32 ENDP

VM_FALCON_TINY_END_ASM32 PROC

    push    eax
    push    ebx
    push    ecx

    mov     eax, 'TMWL'
    mov     ebx, 617
    mov     ecx, 'TMWL'
    add     ebx, eax
    add     ecx, eax

    pop     ecx
    pop     ebx
    pop     eax
    ret

VM_FALCON_TINY_END_ASM32 ENDP

ENDIF

END
