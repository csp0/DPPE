% === Time To First Authenticated Channel (TTFAC) Comparison ===
clc; clear; close all;

t = 0:1:200; % from 0 sec to 200 sec

% Standard Chimera (Slow Channel): 180 sec(10 frames) delayed
std_auth = zeros(size(t));
std_auth(t >= 180) = 1;

% Enhanced Chimera (Proposed): 36 sec (2 frames) delayed
enh_auth = zeros(size(t));
enh_auth(t >= 36) = 1;

figure('Name', 'Authentication Latency', 'Color', 'w', 'Position', [150, 150, 600, 450]); %[output:617755ce]
stairs(t, std_auth, '--b', 'LineWidth', 2.5); hold on; %[output:617755ce]
stairs(t, enh_auth, '-r', 'LineWidth', 2.5); %[output:617755ce]

fill([36 180 180 36], [0 0 1 1], 'g', 'FaceAlpha', 0.1, 'EdgeColor', 'none'); %[output:617755ce]
text(108, 0.5, '\leftarrow 80% Time Reduction \rightarrow', 'HorizontalAlignment', 'center', 'FontSize', 12, 'FontWeight', 'bold', 'Color', [0 0.5 0]); %[output:617755ce]

grid on; %[output:617755ce]
xlabel('Observation Time (seconds)', 'FontSize', 12, 'FontWeight', 'bold'); %[output:617755ce]
ylabel('Cumulative Probability of Authentication', 'FontSize', 12, 'FontWeight', 'bold'); %[output:617755ce]
title('Time To First Authenticated Channel (TTFAC)', 'FontSize', 13, 'FontWeight', 'bold'); %[output:617755ce]

ylim([-0.1 1.2]); yticks([0 1]); yticklabels({'0', '1'}); %[output:617755ce]

legend('Standard Chimera (Slow Channel)', 'Enhanced Chimera (Proposed)', 'Location', 'east'); %[output:617755ce]
set(gca, 'FontSize', 11); %[output:617755ce]

