% === Payload BER vs. Duty Factor (40 dB-Hz) ===
clc; clear; close all;

fprintf('Payload BER (spreading gain) Analysis: starting simulation...\n'); %[output:3f20874e]

target_CN0_dBHz = 40;
df_test_array = 1:5; 

sim_uncoded_ber = zeros(length(df_test_array), 1);
sim_coded_ber = zeros(length(df_test_array), 1);

PRNID = 7; f_chip = 1.023e6; fs = f_chip * 24; samples_per_chip = fs / f_chip;
[L1Cd, L1Cp, L1Co] = gpsL1CCodes(PRNID);
L1Co_expanded = repelem(L1Co, 10230, 1); L1Cp_expanded = repmat(L1Cp, 1800, 1);    
L1Co_sig = 1 - 2*double(L1Co_expanded);  L1Cp_sig = 1 - 2*double(L1Cp_expanded);	               	    

slowFast = 0; zcount = 902044820;  
hexKey = '2B7E151628AED2A6ABF7158809CF4F3C'; secret_key = hexToBits(hexKey);
sector_pattern = get_sector_pattern();
num_symbols_to_process = 1800; 

enhanced_payload_bits = randi([0 1], 900, 1); 
trellis_enhanced = poly2trellis(7, [171 133]);
enhanced_coded_bits = convenc(enhanced_payload_bits, trellis_enhanced); 
enhanced_coded_bpsk = 1 - 2 * double(enhanced_coded_bits); 

for df_idx = 1:length(df_test_array) %[output:group:3664ddba]
    duty_factor = df_test_array(df_idx);
    fprintf('\n▶ Duty Factor = %d Testing...\n', duty_factor); %[output:40f8f5b8] %[output:94ab0936] %[output:7501c725] %[output:02b943ab] %[output:5b0f8737]
    
    combined_Psig = L1Cp_sig .* L1Co_sig; 
    for symIdx = 0:(num_symbols_to_process - 1)
        [marker_indices, marker_symbols] = marker_overlay_symbol( ...
            PRNID, slowFast, zcount, duty_factor, symIdx, secret_key, sector_pattern);
        enhanced_marker_symbols = marker_symbols(:) .* enhanced_coded_bpsk(symIdx + 1);
        absolute_indices = symIdx * 10230 + marker_indices;
        combined_Psig(absolute_indices) = enhanced_marker_symbols;
    end

    % Baseband AWGN generation
    req_SNR_dB = target_CN0_dBHz - 10*log10(f_chip);
    rx_sig = awgn(combined_Psig, req_SNR_dB, 'measured');
    
    soft_decision_values = zeros(num_symbols_to_process, 1); 
    for step = 1:num_symbols_to_process
        symIdx_rx = step - 1; 
        [expected_indices, expected_symbols] = marker_overlay_symbol( ...
            PRNID, slowFast, zcount, duty_factor, symIdx_rx, secret_key, sector_pattern);
        
        idx_start = (step - 1) * 10230 + 1; idx_end = step * 10230;
        extracted_rx_chips = rx_sig(idx_start : idx_end);
        despread_chips = extracted_rx_chips(expected_indices) .* expected_symbols(:);
        soft_decision_values(step) = sum(despread_chips);
    end
    
    % Uncoded BER
    recovered_uncoded_bits = soft_decision_values < 0;
    sim_uncoded_ber(df_idx) = sum(recovered_uncoded_bits ~= enhanced_coded_bits) / num_symbols_to_process;
    
    % Viterbi Coded BER
    recovered_enhanced_payload = vitdec(soft_decision_values, trellis_enhanced, 35, 'trunc', 'unquant');
    sim_coded_ber(df_idx) = sum(recovered_enhanced_payload ~= enhanced_payload_bits) / length(enhanced_payload_bits);
    
    fprintf('   Uncoded BER: %.4f | Viterbi BER: %.4f\n', sim_uncoded_ber(df_idx), sim_coded_ber(df_idx)); %[output:559a77f1] %[output:464beed8] %[output:59032a47] %[output:26ad3d04] %[output:0f7abc06]
end %[output:group:3664ddba]

plot_coded = sim_coded_ber; plot_coded(plot_coded == 0) = 1e-4;

plot_uncoded = sim_uncoded_ber; plot_uncoded(plot_uncoded == 0) = 1e-4; 

figure('Name', 'Payload BER vs Duty Factor', 'Color', 'w', 'Position', [750, 150, 600, 450]); %[output:9c696b55]

semilogy(df_test_array, plot_uncoded, 'bs-', 'LineWidth', 1.5, 'MarkerSize', 8); hold on; %[output:9c696b55]
semilogy(df_test_array, plot_coded, 'ro-', 'LineWidth', 2, 'MarkerSize', 8, 'MarkerFaceColor', 'r'); %[output:9c696b55]

grid on; %[output:9c696b55]
xlabel('Duty Factor (Markers per 33-chip segment)', 'FontSize', 12, 'FontWeight', 'bold'); %[output:9c696b55]
ylabel('Bit Error Rate (BER)', 'FontSize', 12, 'FontWeight', 'bold'); %[output:9c696b55]
title(sprintf('Authentication Payload Extraction (C/N_0 = %d dB-Hz)', target_CN0_dBHz), 'FontSize', 13, 'FontWeight', 'bold'); %[output:9c696b55]
ylim([1e-4, 0.5]); yticks([1e-4, 1e-3, 1e-2, 1e-1, 1]); %[output:9c696b55]
yticklabels({'0', '10^{-3}', '10^{-2}', '10^{-1}', '10^{0}'}); %[output:9c696b55]
xticks(df_test_array); %[output:9c696b55]
legend('Simulated Un-coded BER', 'Viterbi Decoded BER', 'Location', 'southwest'); %[output:9c696b55]
set(gca, 'FontSize', 11); %[output:9c696b55]
