/**
 * SecureAuth Content Script
 * Monitors login forms and performs multi-signal phishing detection
 */

class SecureAuthMonitor {
  constructor() {
    this.loginForms = new Set();
    this.detectionResults = {};
    this.isAnalyzing = false;
    
    // Known legitimate login domains for major services
    this.trustedDomains = [
      'google.com', 'microsoft.com', 'facebook.com', 'apple.com',
      'github.com', 'linkedin.com', 'twitter.com', 'amazon.com',
      'yahoo.com', 'dropbox.com', 'salesforce.com'
    ];
    
    this.init();
  }

  init() {
    console.log('[SecureAuth] Initializing protection...');
    
    // Monitor form submissions
    document.addEventListener('submit', (e) => this.handleFormSubmit(e), true);
    
    // Monitor password field changes
    document.addEventListener('input', (e) => {
      if (e.target.type === 'password') {
        this.monitorPasswordField(e.target);
      }
    }, true);
    
    // Scan for existing forms
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.scanForLoginForms());
    } else {
      this.scanForLoginForms();
    }
    
    // Monitor DOM changes for dynamically added forms
    this.observeDOM();
  }

  scanForLoginForms() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
      const form = field.closest('form');
      if (form && !this.loginForms.has(form)) {
        this.loginForms.add(form);
        this.analyzeForm(form);
      }
    });
  }

  observeDOM() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) { // Element node
            if (node.matches && node.matches('input[type="password"]')) {
              this.scanForLoginForms();
            } else if (node.querySelectorAll) {
              const passwordFields = node.querySelectorAll('input[type="password"]');
              if (passwordFields.length > 0) {
                this.scanForLoginForms();
              }
            }
          }
        });
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  async handleFormSubmit(event) {
    const form = event.target;
    
    // Check if this is a login form
    const passwordField = form.querySelector('input[type="password"]');
    if (!passwordField || !passwordField.value) {
      return;
    }

    const usernameField = this.findUsernameField(form);
    if (!usernameField || !usernameField.value) {
      return;
    }

    // Prevent submission while we analyze
    event.preventDefault();
    event.stopPropagation();

    console.log('[SecureAuth] Login attempt detected, analyzing...');

    // Perform comprehensive security analysis
    const analysisResults = await this.performSecurityAnalysis(
      passwordField.value,
      usernameField.value,
      form
    );

    // Calculate risk score
    const riskScore = this.calculateRiskScore(analysisResults);

    // Take action based on risk level
    await this.handleRiskDecision(riskScore, analysisResults, form, event);
  }

  findUsernameField(form) {
    // Common username field patterns
    const selectors = [
      'input[type="email"]',
      'input[type="text"][name*="user"]',
      'input[type="text"][name*="email"]',
      'input[type="text"][name*="login"]',
      'input[type="text"][id*="user"]',
      'input[type="text"][id*="email"]',
      'input[type="text"][id*="login"]',
      'input[autocomplete="username"]',
      'input[autocomplete="email"]'
    ];

    for (const selector of selectors) {
      const field = form.querySelector(selector);
      if (field && field.value) {
        return field;
      }
    }

    // Fallback: find first text input before password
    const allInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
    return allInputs.length > 0 ? allInputs[0] : null;
  }

  async performSecurityAnalysis(password, username, form) {
    const results = {
      domain: this.analyzeDomain(),
      certificate: await this.analyzeCertificate(),
      breachCheck: await this.checkPasswordBreach(password),
      formCharacteristics: this.analyzeFormCharacteristics(form),
      visualSimilarity: this.analyzeVisualSimilarity(),
      domainReputation: await this.checkDomainReputation()
    };

    console.log('[SecureAuth] Analysis results:', results);
    return results;
  }

  analyzeDomain() {
    const url = new URL(window.location.href);
    const hostname = url.hostname;
    
    const analysis = {
      hostname: hostname,
      protocol: url.protocol,
      isTrusted: false,
      suspiciousPatterns: [],
      score: 50 // Neutral starting point
    };

    // Check if domain is in trusted list
    for (const trustedDomain of this.trustedDomains) {
      if (hostname === trustedDomain || hostname.endsWith('.' + trustedDomain)) {
        analysis.isTrusted = true;
        analysis.score = 90;
        break;
      }
    }

    // Check for suspicious patterns
    if (hostname.includes('login') && !analysis.isTrusted) {
      analysis.suspiciousPatterns.push('Contains "login" in subdomain');
      analysis.score -= 20;
    }

    if (hostname.includes('secure') && !analysis.isTrusted) {
      analysis.suspiciousPatterns.push('Contains "secure" in domain');
      analysis.score -= 15;
    }

    // Check for homograph attacks (lookalike characters)
    if (this.containsHomographs(hostname)) {
      analysis.suspiciousPatterns.push('Possible homograph attack detected');
      analysis.score -= 30;
    }

    // Check for unusual TLDs
    const tld = hostname.split('.').pop();
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top'];
    if (suspiciousTLDs.includes(tld)) {
      analysis.suspiciousPatterns.push('Suspicious TLD: ' + tld);
      analysis.score -= 25;
    }

    // Check protocol
    if (url.protocol !== 'https:') {
      analysis.suspiciousPatterns.push('Not using HTTPS');
      analysis.score -= 40;
    }

    return analysis;
  }

  containsHomographs(hostname) {
    // Check for common homograph characters used in phishing
    const homographChars = /[а-яА-Я]/; // Cyrillic characters
    return homographChars.test(hostname);
  }

  async analyzeCertificate() {
    // Note: In a real browser extension, we'd use the webRequest API
    // to inspect SSL certificates. For this implementation, we'll
    // simulate based on available information.
    
    const analysis = {
      isSecure: window.location.protocol === 'https:',
      score: 50
    };

    if (analysis.isSecure) {
      analysis.score = 70;
    } else {
      analysis.warning = 'Not using HTTPS - highly suspicious for login';
      analysis.score = 10;
    }

    return analysis;
  }

  async checkPasswordBreach(password) {
    try {
      // Use HIBP API with k-anonymity model
      const sha1Hash = await this.sha1(password);
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5).toUpperCase();

      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        method: 'GET',
        headers: {
          'Add-Padding': 'true' // Enhanced privacy
        }
      });

      if (!response.ok) {
        console.warn('[SecureAuth] HIBP API unavailable');
        return { checked: false, found: false, score: 50 };
      }

      const data = await response.text();
      const hashes = data.split('\n');
      
      for (const line of hashes) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix === suffix) {
          return {
            checked: true,
            found: true,
            count: parseInt(count),
            score: 0, // Breached password = very suspicious
            warning: `Password found in ${count} data breaches`
          };
        }
      }

      return {
        checked: true,
        found: false,
        score: 80 // Clean password = more likely legitimate site
      };

    } catch (error) {
      console.error('[SecureAuth] Breach check failed:', error);
      return { checked: false, found: false, score: 50 };
    }
  }

  async sha1(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  analyzeFormCharacteristics(form) {
    const analysis = {
      hasProperLabels: false,
      hasRememberMe: false,
      hasForgotPassword: false,
      hasRegisterLink: false,
      suspiciousIframes: false,
      score: 50
    };

    // Check for proper labels
    const labels = form.querySelectorAll('label');
    if (labels.length >= 2) {
      analysis.hasProperLabels = true;
      analysis.score += 10;
    }

    // Check for "Remember Me" checkbox
    const checkboxes = form.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(cb => {
      const label = form.querySelector(`label[for="${cb.id}"]`);
      if (label && /remember/i.test(label.textContent)) {
        analysis.hasRememberMe = true;
        analysis.score += 5;
      }
    });

    // Check for "Forgot Password" link
    const links = form.querySelectorAll('a');
    links.forEach(link => {
      if (/forgot|reset/i.test(link.textContent)) {
        analysis.hasForgotPassword = true;
        analysis.score += 10;
      }
      if (/register|sign up|create account/i.test(link.textContent)) {
        analysis.hasRegisterLink = true;
        analysis.score += 5;
      }
    });

    // Check for suspicious iframes
    if (document.querySelectorAll('iframe').length > 0 && 
        !this.analyzeDomain().isTrusted) {
      analysis.suspiciousIframes = true;
      analysis.score -= 20;
    }

    return analysis;
  }

  analyzeVisualSimilarity() {
    // Analyze page for common phishing visual patterns
    const analysis = {
      hasOfficialBranding: false,
      suspiciousElements: [],
      score: 50
    };

    // Check for common phishing indicators
    const bodyText = document.body.textContent.toLowerCase();
    
    if (bodyText.includes('verify') && bodyText.includes('account')) {
      analysis.suspiciousElements.push('Account verification language');
      analysis.score -= 10;
    }

    if (bodyText.includes('suspend') || bodyText.includes('locked')) {
      analysis.suspiciousElements.push('Urgency language detected');
      analysis.score -= 15;
    }

    if (bodyText.includes('unusual activity')) {
      analysis.suspiciousElements.push('Security scare tactics');
      analysis.score -= 15;
    }

    return analysis;
  }

  async checkDomainReputation() {
    // In production, this would integrate with services like:
    // - Google Safe Browsing API
    // - PhishTank API
    // - VirusTotal API
    
    // For this implementation, we'll simulate based on domain age and characteristics
    const hostname = window.location.hostname;
    
    const analysis = {
      checked: true,
      score: 50,
      warnings: []
    };

    // Check if domain is very new (simulated)
    // In production, use a WHOIS lookup service or domain reputation API
    
    return analysis;
  }

  calculateRiskScore(results) {
    let totalScore = 0;
    let weights = {
      domain: 0.30,
      certificate: 0.15,
      breachCheck: 0.25,
      formCharacteristics: 0.15,
      visualSimilarity: 0.10,
      domainReputation: 0.05
    };

    for (const [key, weight] of Object.entries(weights)) {
      if (results[key] && results[key].score !== undefined) {
        totalScore += results[key].score * weight;
      }
    }

    return {
      overall: totalScore,
      level: this.getRiskLevel(totalScore),
      details: results
    };
  }

  getRiskLevel(score) {
    if (score >= 70) return 'LOW';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'HIGH';
    return 'CRITICAL';
  }

  async handleRiskDecision(riskScore, analysisResults, form, originalEvent) {
    console.log('[SecureAuth] Risk Score:', riskScore);

    if (riskScore.level === 'CRITICAL' || riskScore.level === 'HIGH') {
      // Block submission and show strong warning
      this.showBlockingWarning(riskScore, analysisResults);
      
      // Log the blocked attempt
      this.logBlockedAttempt(riskScore);
      
      return; // Don't allow form submission
    }

    if (riskScore.level === 'MEDIUM') {
      // Show warning but allow user to proceed
      const userChoice = await this.showWarningWithChoice(riskScore, analysisResults);
      
      if (userChoice === 'proceed') {
        this.allowFormSubmission(form, originalEvent);
      }
      return;
    }

    // LOW risk - allow submission
    this.allowFormSubmission(form, originalEvent);
  }

  showBlockingWarning(riskScore, analysisResults) {
    // Create overlay warning
    const overlay = document.createElement('div');
    overlay.id = 'secureauth-warning-overlay';
    overlay.innerHTML = `
      <div class="secureauth-modal">
        <div class="secureauth-header critical">
          <span class="secureauth-icon">⚠️</span>
          <h2>PHISHING ATTEMPT BLOCKED</h2>
        </div>
        <div class="secureauth-body">
          <p><strong>SecureAuth has detected a high-risk phishing attempt.</strong></p>
          <p>Risk Level: <span class="risk-badge ${riskScore.level.toLowerCase()}">${riskScore.level}</span></p>
          <p>Score: ${Math.round(riskScore.overall)}/100</p>
          
          <h3>Security Issues Detected:</h3>
          <ul>
            ${this.generateWarningList(analysisResults)}
          </ul>
          
          <div class="secureauth-advice">
            <h3>What should you do?</h3>
            <ul>
              <li>Close this page immediately</li>
              <li>Do NOT enter your credentials</li>
              <li>Navigate directly to the legitimate website</li>
              <li>Change your password if you already submitted it</li>
              <li>Report this phishing site</li>
            </ul>
          </div>
        </div>
        <div class="secureauth-footer">
          <button id="secureauth-close-btn" class="btn-primary">Close This Page</button>
          <button id="secureauth-report-btn" class="btn-secondary">Report Phishing</button>
        </div>
      </div>
    `;

    this.injectStyles();
    document.body.appendChild(overlay);

    // Event listeners
    document.getElementById('secureauth-close-btn').addEventListener('click', () => {
      window.close();
      // If window.close() doesn't work (not opened by script), redirect to safe page
      setTimeout(() => {
        window.location.href = 'about:blank';
      }, 100);
    });

    document.getElementById('secureauth-report-btn').addEventListener('click', () => {
      this.reportPhishingSite();
    });
  }

  async showWarningWithChoice(riskScore, analysisResults) {
    return new Promise((resolve) => {
      const overlay = document.createElement('div');
      overlay.id = 'secureauth-warning-overlay';
      overlay.innerHTML = `
        <div class="secureauth-modal">
          <div class="secureauth-header warning">
            <span class="secureauth-icon">⚠️</span>
            <h2>Security Warning</h2>
          </div>
          <div class="secureauth-body">
            <p><strong>This login page has suspicious characteristics.</strong></p>
            <p>Risk Level: <span class="risk-badge ${riskScore.level.toLowerCase()}">${riskScore.level}</span></p>
            <p>Score: ${Math.round(riskScore.overall)}/100</p>
            
            <h3>Concerns:</h3>
            <ul>
              ${this.generateWarningList(analysisResults)}
            </ul>
            
            <p class="warning-text">Are you sure you want to continue?</p>
          </div>
          <div class="secureauth-footer">
            <button id="secureauth-cancel-btn" class="btn-primary">Cancel Login</button>
            <button id="secureauth-proceed-btn" class="btn-danger">I'm Sure, Proceed</button>
          </div>
        </div>
      `;

      this.injectStyles();
      document.body.appendChild(overlay);

      document.getElementById('secureauth-cancel-btn').addEventListener('click', () => {
        overlay.remove();
        resolve('cancel');
      });

      document.getElementById('secureauth-proceed-btn').addEventListener('click', () => {
        overlay.remove();
        resolve('proceed');
      });
    });
  }

  generateWarningList(analysisResults) {
    const warnings = [];

    if (analysisResults.domain.suspiciousPatterns.length > 0) {
      warnings.push(...analysisResults.domain.suspiciousPatterns.map(p => `<li>🌐 ${p}</li>`));
    }

    if (analysisResults.breachCheck.found) {
      warnings.push(`<li>🔓 ${analysisResults.breachCheck.warning}</li>`);
    }

    if (analysisResults.certificate.warning) {
      warnings.push(`<li>🔒 ${analysisResults.certificate.warning}</li>`);
    }

    if (analysisResults.visualSimilarity.suspiciousElements.length > 0) {
      warnings.push(...analysisResults.visualSimilarity.suspiciousElements.map(e => `<li>👁️ ${e}</li>`));
    }

    if (analysisResults.formCharacteristics.suspiciousIframes) {
      warnings.push('<li>⚠️ Suspicious iframes detected</li>');
    }

    if (!analysisResults.domain.isTrusted) {
      warnings.push('<li>⚠️ Domain not recognized as a trusted service</li>');
    }

    return warnings.length > 0 ? warnings.join('') : '<li>Multiple risk factors detected</li>';
  }

  allowFormSubmission(form, originalEvent) {
    console.log('[SecureAuth] Allowing form submission');
    
    // Re-dispatch the submit event
    // Note: We need to temporarily disable our listener to avoid infinite loop
    document.removeEventListener('submit', this.handleFormSubmit, true);
    
    form.submit();
    
    // Re-enable listener after a delay
    setTimeout(() => {
      document.addEventListener('submit', (e) => this.handleFormSubmit(e), true);
    }, 1000);
  }

  async logBlockedAttempt(riskScore) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      url: window.location.href,
      hostname: window.location.hostname,
      riskScore: riskScore.overall,
      riskLevel: riskScore.level
    };

    // Send to background script for storage
    chrome.runtime.sendMessage({
      action: 'logBlockedAttempt',
      data: logEntry
    });
  }

  reportPhishingSite() {
    const reportUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(window.location.href)}`;
    window.open(reportUrl, '_blank');
  }

  monitorPasswordField(field) {
    // Add visual indicator that field is being monitored
    if (!field.dataset.secureauthMonitored) {
      field.dataset.secureauthMonitored = 'true';
      
      // Could add a small icon indicator here if desired
    }
  }

  analyzeForm(form) {
    // Initial form analysis - could be expanded
    console.log('[SecureAuth] Monitoring login form');
  }

  injectStyles() {
    if (document.getElementById('secureauth-styles')) return;

    const style = document.createElement('style');
    style.id = 'secureauth-styles';
    style.textContent = `
      #secureauth-warning-overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }

      .secureauth-modal {
        background: white;
        border-radius: 12px;
        max-width: 600px;
        width: 90%;
        max-height: 90vh;
        overflow-y: auto;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
      }

      .secureauth-header {
        padding: 24px;
        border-bottom: 1px solid #e0e0e0;
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .secureauth-header.critical {
        background: #dc3545;
        color: white;
        border-bottom: none;
      }

      .secureauth-header.warning {
        background: #ff9800;
        color: white;
        border-bottom: none;
      }

      .secureauth-icon {
        font-size: 32px;
      }

      .secureauth-header h2 {
        margin: 0;
        font-size: 24px;
        font-weight: 600;
      }

      .secureauth-body {
        padding: 24px;
      }

      .secureauth-body p {
        margin: 12px 0;
        font-size: 16px;
        line-height: 1.5;
      }

      .secureauth-body h3 {
        margin: 20px 0 12px 0;
        font-size: 18px;
        font-weight: 600;
        color: #333;
      }

      .secureauth-body ul {
        margin: 12px 0;
        padding-left: 24px;
      }

      .secureauth-body li {
        margin: 8px 0;
        font-size: 15px;
        line-height: 1.5;
      }

      .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 14px;
      }

      .risk-badge.critical {
        background: #dc3545;
        color: white;
      }

      .risk-badge.high {
        background: #ff6b6b;
        color: white;
      }

      .risk-badge.medium {
        background: #ff9800;
        color: white;
      }

      .risk-badge.low {
        background: #4caf50;
        color: white;
      }

      .secureauth-advice {
        background: #f8f9fa;
        padding: 16px;
        border-radius: 8px;
        margin-top: 20px;
      }

      .warning-text {
        font-weight: 600;
        color: #ff9800;
        margin-top: 20px;
      }

      .secureauth-footer {
        padding: 20px 24px;
        border-top: 1px solid #e0e0e0;
        display: flex;
        gap: 12px;
        justify-content: flex-end;
      }

      .secureauth-footer button {
        padding: 12px 24px;
        border: none;
        border-radius: 6px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
      }

      .btn-primary {
        background: #007bff;
        color: white;
      }

      .btn-primary:hover {
        background: #0056b3;
      }

      .btn-secondary {
        background: #6c757d;
        color: white;
      }

      .btn-secondary:hover {
        background: #545b62;
      }

      .btn-danger {
        background: #dc3545;
        color: white;
      }

      .btn-danger:hover {
        background: #c82333;
      }
    `;

    document.head.appendChild(style);
  }
}

// Initialize the monitor
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    new SecureAuthMonitor();
  });
} else {
  new SecureAuthMonitor();
}
