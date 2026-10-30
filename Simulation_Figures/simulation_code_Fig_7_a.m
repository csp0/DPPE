% Total Authentication Success Rate vs. C/N0 ===
clc; clear; close all;

cn0 = 32:0.5:45; 
cn0_linear = 10.^(cn0/10);

% 1. Marker detection prob. (Pd) based on Marcum Q-function (Tint=10ms, DF=2)
T_int = 0.01; df_ratio = 2/33; P_fa = 1e-3;
snr_eff = 2 * T_int * (1 - df_ratio) * cn0_linear;
V_th = sqrt(-2 * log(P_fa));
Pd = marcumq(sqrt(2 * snr_eff), V_th);

% 2. Viterbi decoding BER and FER 
ber_coded = 0.5 * erfc(sqrt(10.^((cn0-36)/10))); 
ber_coded(cn0 >= 40) = 0; % Error-free over 40 dB-Hz
FER = 1 - (1 - ber_coded).^900; % Frame error rate for 900-bit frame

% 3. Total authentication success rate prob. (ASR = Pd * (1 - FER))
ASR = Pd .* (1 - FER);

figure('Name', 'Total Authentication Success Rate', 'Color', 'w', 'Position', [100, 100, 600, 450]); %[output:2040ae54]
plot(cn0, Pd, '-b', 'LineWidth', 2.5); hold on; %[output:2040ae54]

plot(cn0 - 0.1, 1-FER, '--g', 'LineWidth', 2.5); %[output:2040ae54]

plot(cn0, ASR, '-r', 'LineWidth', 2, 'Marker', 'o', 'MarkerSize', 6); %[output:2040ae54]

grid on; %[output:2040ae54]

xlim([32 46]); %[output:2040ae54]
ylim([-0.05 1.05]);  %[output:2040ae54]

xlabel('Received C/N_0 (dB-Hz)', 'FontSize', 12, 'FontWeight', 'bold'); %[output:2040ae54]
ylabel('Probability', 'FontSize', 12, 'FontWeight', 'bold'); %[output:2040ae54]
title('Total Authentication Success Rate', 'FontSize', 13, 'FontWeight', 'bold'); %[output:2040ae54]
legend('Detection Prob. (P_d)', 'Payload Recovery Prob. (1 - FERcoded)', 'Total Success Rate (ASR)', 'Location', 'northwest'); %[output:2040ae54]
set(gca, 'FontSize', 11); %[output:2040ae54]

