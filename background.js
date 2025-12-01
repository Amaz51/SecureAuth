/**
 * SecureAuth Background Service Worker
 * Handles extension state, logging, and communication with content scripts
 */

class SecureAuthBackground {
  constructor() {
    this.blockedAttempts = [];
    this.statistics = {
      totalScans: 0,
      blockedAttempts: 0,
      warningsShown: 0,
      allowedLogins: 0
    };
    
    this.init();
  }

  init() {
    console.log('[SecureAuth Background] Service worker initialized');
    
    // Listen for messages from content scripts
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      this.handleMessage(request, sender, sendResponse);
      return true; // Keep channel open for async response
    });

    // Load stored data
    this.loadStoredData();

    // Set up periodic cleanup
    this.setupPeriodicCleanup();
  }

  handleMessage(request, sender, sendResponse) {
    switch (request.action) {
      case 'logBlockedAttempt':
        this.logBlockedAttempt(request.data);
        sendResponse({ success: true });
        break;

      case 'getStatistics':
        sendResponse({ statistics: this.statistics });
        break;

      case 'getBlockedAttempts':
        sendResponse({ attempts: this.blockedAttempts });
        break;

      case 'clearHistory':
        this.clearHistory();
        sendResponse({ success: true });
        break;

      case 'updateSettings':
        this.updateSettings(request.settings);
        sendResponse({ success: true });
        break;

      default:
        sendResponse({ error: 'Unknown action' });
    }
  }

  logBlockedAttempt(data) {
    console.log('[SecureAuth] Logging blocked attempt:', data);
    
    this.blockedAttempts.unshift(data);
    
    // Keep only last 100 attempts
    if (this.blockedAttempts.length > 100) {
      this.blockedAttempts = this.blockedAttempts.slice(0, 100);
    }

    this.statistics.blockedAttempts++;
    
    // Save to storage
    this.saveData();

    // Show notification
    this.showNotification(data);
  }

  showNotification(data) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'SecureAuth: Phishing Attempt Blocked',
      message: `Blocked suspicious login attempt on ${data.hostname}`,
      priority: 2
    });
  }

  async loadStoredData() {
    try {
      const result = await chrome.storage.local.get(['blockedAttempts', 'statistics', 'settings']);
      
      if (result.blockedAttempts) {
        this.blockedAttempts = result.blockedAttempts;
      }
      
      if (result.statistics) {
        this.statistics = result.statistics;
      }

      if (result.settings) {
        this.settings = result.settings;
      }

      console.log('[SecureAuth] Loaded stored data');
    } catch (error) {
      console.error('[SecureAuth] Error loading data:', error);
    }
  }

  async saveData() {
    try {
      await chrome.storage.local.set({
        blockedAttempts: this.blockedAttempts,
        statistics: this.statistics,
        settings: this.settings
      });
    } catch (error) {
      console.error('[SecureAuth] Error saving data:', error);
    }
  }

  clearHistory() {
    this.blockedAttempts = [];
    this.statistics = {
      totalScans: 0,
      blockedAttempts: 0,
      warningsShown: 0,
      allowedLogins: 0
    };
    
    this.saveData();
  }

  updateSettings(newSettings) {
    this.settings = { ...this.settings, ...newSettings };
    this.saveData();
  }

  setupPeriodicCleanup() {
    // Clean up old entries every hour
    setInterval(() => {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

      this.blockedAttempts = this.blockedAttempts.filter(attempt => {
        const attemptDate = new Date(attempt.timestamp);
        return attemptDate > oneWeekAgo;
      });

      this.saveData();
    }, 3600000); // 1 hour
  }
}

// Initialize background service
const secureAuthBackground = new SecureAuthBackground();

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  chrome.tabs.create({ url: 'popup.html' });
});
