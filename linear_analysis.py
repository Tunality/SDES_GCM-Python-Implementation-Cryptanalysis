def get_lat(box):
    # A simplified LAT for a 4x4 S-box (input 4-bit, output 2-bit)
    # This checks how often (Input_Bits ^ Output_Bits) == 0
    lat = [[0] * 4 for _ in range(16)] # 16 input masks, 4 output masks
    
    for val_in in range(16):
        # Extract row/col bits like your sbox function does
        bits = [int(b) for b in format(val_in, '04b')]
        row = int(f"{bits[0]}{bits[3]}", 2)
        col = int(f"{bits[1]}{bits[2]}", 2)
        val_out = box[row][col]
        
        for mask_in in range(16):
            for mask_out in range(4):
                # Parity of (In & MaskIn) XOR (Out & MaskOut)
                p_in = bin(val_in & mask_in).count('1') % 2
                p_out = bin(val_out & mask_out).count('1') % 2
                if p_in == p_out:
                    lat[mask_in][mask_out] += 1
    return lat

def run_analysis():
    print("\n[!] Performing Linear Cryptanalysis (S-Box Bias Mapping)")
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    lat = get_lat(S0)
    
    print("Linear Approximation Table (Sample of S0):")
    print("Input Mask | Out Mask 1 | Out Mask 2 | Out Mask 3")
    for i in range(5): # Just show first 5 for brevity
        row = " | ".join(str(val - 8).rjust(10) for val in lat[i][1:])
        print(f"    {i}      | {row}")
    
    print("\nInterpretation: Values far from 0 (like -4 or +4) indicate a 'Linear Bias'.")
    print("Attacker uses these biases to guess key bits with > 50% accuracy.")