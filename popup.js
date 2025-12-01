/**
 * SecureAuth Popup Script
 * Handles dashboard UI and user interactions
 */

class SecureAuthDashboard {
  constructor() {
    this.statistics = null;
    this.blockedAttempts = [];
    this.init();
  }

  async init() {
    console.log('[SecureAuth Dashboard] Initializing...');
    
    await this.loadData();
    this.updateUI();
    this.setupEventListeners();
  }

  async loadData() {
    try {
      // Get statistics from background script
      const statsResponse = await chrome.runtime.sendMessage({ action: 'getStatistics' });
      this.statistics = statsResponse.statistics;

      // Get blocked attempts
      const attemptsResponse = await chrome.runtime.sendMessage({ action: 'getBlockedAttempts' });
      this.blockedAttempts = attemptsResponse.attempts || [];

      console.log('[SecureAuth Dashboard] Data loaded:', this.statistics);
    } catch (error) {
      console.error('[SecureAuth Dashboard] Error loading data:', error);
      // Initialize with default values
      this.statistics = {
        totalScans: 0,
        blockedAttempts: 0,
        warningsShown: 0,
        allowedLogins: 0
      };
    }
  }

  updateUI() {
    // Update statistics
    document.getElementById('blocked-count').textContent = this.statistics.blockedAttempts || 0;
    document.getElementById('scan-count').textContent = this.statistics.totalScans || 0;
    document.getElementById('warning-count').textContent = this.statistics.warningsShown || 0;

    // Update recent activity
    this.updateRecentActivity();
  }

  updateRecentActivity() {
    const activityContainer = document.getElementById('recent-activity');
    
    if (this.blockedAttempts.length === 0) {
      activityContainer.innerHTML = `
        <div class="empty-state">
          <p>No threats detected yet. SecureAuth is actively protecting you!</p>
        </div>
      `;
      return;
    }

    // Show last 5 attempts
    const recentAttempts = this.blockedAttempts.slice(0, 5);
    
    activityContainer.innerHTML = recentAttempts.map(attempt => `
      <div class="activity-item">
        <div class="activity-icon ${attempt.riskLevel.toLowerCase()}">⚠️</div>
        <div class="activity-details">
          <div class="activity-url">${this.truncateUrl(attempt.hostname)}</div>
          <div class="activity-meta">
            <span class="risk-badge ${attempt.riskLevel.toLowerCase()}">${attempt.riskLevel}</span>
            <span class="activity-time">${this.formatTime(attempt.timestamp)}</span>
          </div>
        </div>
      </div>
    `).join('');
  }

  setupEventListeners() {
    // View History Button
    document.getElementById('view-history-btn').addEventListener('click', () => {
      this.showHistoryModal();
    });

    // Settings Button
    document.getElementById('settings-btn').addEventListener('click', () => {
      this.showSettingsModal();
    });

    // Clear History Button
    document.getElementById('clear-history-btn').addEventListener('click', () => {
      this.clearHistory();
    });

    // About Link
    document.getElementById('about-link').addEventListener('click', (e) => {
      e.preventDefault();
      this.showAboutModal();
    });

    // Help Link
    document.getElementById('help-link').addEventListener('click', (e) => {
      e.preventDefault();
      this.showHelpModal();
    });

    // Modal Close Buttons
    document.getElementById('close-history-modal').addEventListener('click', () => {
      this.hideModal('history-modal');
    });

    document.getElementById('close-settings-modal').addEventListener('click', () => {
      this.hideModal('settings-modal');
    });

    document.getElementById('close-about-modal').addEventListener('click', () => {
      this.hideModal('about-modal');
    });

    // Save Settings Button
    document.getElementById('save-settings-btn').addEventListener('click', () => {
      this.saveSettings();
    });

    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal')) {
        this.hideModal(e.target.id);
      }
    });
  }

  showHistoryModal() {
    const modal = document.getElementById('history-modal');
    const historyList = document.getElementById('history-list');

    if (this.blockedAttempts.length === 0) {
      historyList.innerHTML = `
        <div class="empty-state">
          <p>No blocked attempts in history.</p>
        </div>
      `;
    } else {
      historyList.innerHTML = this.blockedAttempts.map(attempt => `
        <div class="history-item">
          <div class="history-header">
            <span class="history-url">${attempt.url}</span>
            <span class="risk-badge ${attempt.riskLevel.toLowerCase()}">${attempt.riskLevel}</span>
          </div>
          <div class="history-details">
            <p><strong>Hostname:</strong> ${attempt.hostname}</p>
            <p><strong>Risk Score:</strong> ${Math.round(attempt.riskScore)}/100</p>
            <p><strong>Time:</strong> ${this.formatDateTime(attempt.timestamp)}</p>
          </div>
        </div>
      `).join('');
    }

    modal.classList.remove('hidden');
  }

  showSettingsModal() {
    const modal = document.getElementById('settings-modal');
    
    // Load current settings
    chrome.storage.local.get(['settings'], (result) => {
      const settings = result.settings || {
        enableProtection: true,
        enableNotifications: true,
        enableHIBP: true,
        sensitivity: 'medium'
      };

      document.getElementById('enable-protection').checked = settings.enableProtection;
      document.getElementById('enable-notifications').checked = settings.enableNotifications;
      document.getElementById('enable-hibp').checked = settings.enableHIBP;
      document.getElementById('sensitivity').value = settings.sensitivity;
    });

    modal.classList.remove('hidden');
  }

  showAboutModal() {
    const modal = document.getElementById('about-modal');
    modal.classList.remove('hidden');
  }

  showHelpModal() {
    // For now, redirect to a help page or show inline help
    window.open('https://github.com/yourusername/secureauth/wiki', '_blank');
  }

  hideModal(modalId) {
    const modal = document.getElementById(modalId);
    modal.classList.add('hidden');
  }

  async saveSettings() {
    const settings = {
      enableProtection: document.getElementById('enable-protection').checked,
      enableNotifications: document.getElementById('enable-notifications').checked,
      enableHIBP: document.getElementById('enable-hibp').checked,
      sensitivity: document.getElementById('sensitivity').value
    };

    try {
      await chrome.runtime.sendMessage({
        action: 'updateSettings',
        settings: settings
      });

      // Show success message
      this.showToast('Settings saved successfully!');
      
      // Close modal
      this.hideModal('settings-modal');
    } catch (error) {
      console.error('[SecureAuth] Error saving settings:', error);
      this.showToast('Error saving settings', 'error');
    }
  }

  async clearHistory() {
    if (!confirm('Are you sure you want to clear all history? This cannot be undone.')) {
      return;
    }

    try {
      await chrome.runtime.sendMessage({ action: 'clearHistory' });
      
      // Reload data
      await this.loadData();
      this.updateUI();
      
      this.showToast('History cleared successfully!');
    } catch (error) {
      console.error('[SecureAuth] Error clearing history:', error);
      this.showToast('Error clearing history', 'error');
    }
  }

  showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
      toast.classList.add('show');
    }, 100);

    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => {
        toast.remove();
      }, 300);
    }, 3000);
  }

  truncateUrl(url, maxLength = 40) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  formatTime(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return date.toLocaleDateString();
  }

  formatDateTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
  }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new SecureAuthDashboard();
});
