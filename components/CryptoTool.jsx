import React, { useState } from 'react';

function CryptoTool() {
  const [activeTab, setActiveTab] = useState('aes');
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [privateKey, setPrivateKey] = useState('');
  const [nonce, setNonce] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  // Simple AES-like encryption (for demo purposes - not cryptographically secure)
  const simpleAESEncrypt = (text, key) => {
    if (!text || !key) return '';
    let encrypted = '';
    for (let i = 0; i < text.length; i++) {
      const charCode = text.charCodeAt(i) ^ key.charCodeAt(i % key.length);
      encrypted += String.fromCharCode(charCode);
    }
    return btoa(encrypted);
  };

  const simpleAESDecrypt = (encrypted, key) => {
    if (!encrypted || !key) return '';
    try {
      const decoded = atob(encrypted);
      let decrypted = '';
      for (let i = 0; i < decoded.length; i++) {
        const charCode = decoded.charCodeAt(i) ^ key.charCodeAt(i % key.length);
        decrypted += String.fromCharCode(charCode);
      }
      return decrypted;
    } catch {
      return 'Invalid encrypted text';
    }
  };

  // Simple RSA-like encryption simulation
  const simpleRSAEncrypt = (text, key) => {
    if (!text || !key) return '';
    const shift = key.length % 26;
    return text.split('').map(char => {
      if (char.match(/[a-z]/i)) {
        const code = char.charCodeAt(0);
        const base = code >= 65 && code <= 90 ? 65 : 97;
        return String.fromCharCode(((code - base + shift) % 26) + base);
      }
      return char;
    }).join('');
  };

  const simpleRSADecrypt = (text, key) => {
    if (!text || !key) return '';
    const shift = key.length % 26;
    return text.split('').map(char => {
      if (char.match(/[a-z]/i)) {
        const code = char.charCodeAt(0);
        const base = code >= 65 && code <= 90 ? 65 : 97;
        return String.fromCharCode(((code - base - shift + 26) % 26) + base);
      }
      return char;
    }).join('');
  };

  // Simple Curve25519-like encryption simulation
  const simpleCurveEncrypt = (text, key) => {
    if (!text || !key) return '';
    const keyNum = key.split('').reduce((sum, char) => sum + char.charCodeAt(0), 0);
    return text.split('').map(char => {
      const encrypted = char.charCodeAt(0) + (keyNum % 100);
      return encrypted.toString(16);
    }).join('-');
  };

  const simpleCurveDecrypt = (text, key) => {
    if (!text || !key) return '';
    try {
      const keyNum = key.split('').reduce((sum, char) => sum + char.charCodeAt(0), 0);
      return text.split('-').map(hex => {
        const decrypted = parseInt(hex, 16) - (keyNum % 100);
        return String.fromCharCode(decrypted);
      }).join('');
    } catch {
      return 'Invalid encrypted text';
    }
  };

  // Simple ChaCha20-like encryption simulation
  const simpleChaChaEncrypt = (text, key, nonce) => {
    if (!text || !key || !nonce) return '';
    const keyStream = generateKeyStream(key, nonce, text.length);
    let encrypted = '';
    for (let i = 0; i < text.length; i++) {
      const encryptedChar = text.charCodeAt(i) ^ keyStream[i];
      encrypted += encryptedChar.toString(16).padStart(2, '0');
    }
    return encrypted;
  };

  const simpleChaChaDecrypt = (encrypted, key, nonce) => {
    if (!encrypted || !key || !nonce) return '';
    try {
      const encryptedBytes = [];
      for (let i = 0; i < encrypted.length; i += 2) {
        encryptedBytes.push(parseInt(encrypted.substr(i, 2), 16));
      }
      const keyStream = generateKeyStream(key, nonce, encryptedBytes.length);
      let decrypted = '';
      for (let i = 0; i < encryptedBytes.length; i++) {
        const decryptedChar = encryptedBytes[i] ^ keyStream[i];
        decrypted += String.fromCharCode(decryptedChar);
      }
      return decrypted;
    } catch {
      return 'Invalid encrypted text';
    }
  };

  // Generate pseudo-random keystream for ChaCha20 simulation
  const generateKeyStream = (key, nonce, length) => {
    const keyStream = [];
    let seed = 0;
    
    // Create seed from key and nonce
    for (let i = 0; i < key.length; i++) {
      seed += key.charCodeAt(i);
    }
    for (let i = 0; i < nonce.length; i++) {
      seed += nonce.charCodeAt(i) * 7;
    }
    
    // Generate pseudo-random keystream
    for (let i = 0; i < length; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      keyStream.push(seed % 256);
    }
    
    return keyStream;
  };

  const generateRandomKey = (length = 32) => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const generateRandomNonce = (length = 12) => {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const generateRSAKeyPair = () => {
    const publicKey = generateRandomKey(64);
    const privateKey = generateRandomKey(64);
    return { publicKey, privateKey };
  };

  const handleEncrypt = async () => {
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 500)); // Simulate processing

    let result = '';
    switch (activeTab) {
      case 'aes':
        result = simpleAESEncrypt(inputText, secretKey);
        break;
      case 'rsa':
        result = simpleRSAEncrypt(inputText, publicKey);
        break;
      case 'curve25519':
        result = simpleCurveEncrypt(inputText, secretKey);
        break;
      case 'chacha20':
        result = simpleChaChaEncrypt(inputText, secretKey, nonce);
        break;
    }
    setOutputText(result);
    setIsLoading(false);
  };

  const handleDecrypt = async () => {
    setIsLoading(true);
    await new Promise(resolve => setTimeout(resolve, 500)); // Simulate processing

    let result = '';
    switch (activeTab) {
      case 'aes':
        result = simpleAESDecrypt(inputText, secretKey);
        break;
      case 'rsa':
        result = simpleRSADecrypt(inputText, privateKey);
        break;
      case 'curve25519':
        result = simpleCurveDecrypt(inputText, secretKey);
        break;
      case 'chacha20':
        result = simpleChaChaDecrypt(inputText, secretKey, nonce);
        break;
    }
    setOutputText(result);
    setIsLoading(false);
  };

  const handleGenerateKeys = () => {
    if (activeTab === 'rsa') {
      const { publicKey: newPublicKey, privateKey: newPrivateKey } = generateRSAKeyPair();
      setPublicKey(newPublicKey);
      setPrivateKey(newPrivateKey);
    } else {
      setSecretKey(generateRandomKey());
      if (activeTab === 'chacha20') {
        setNonce(generateRandomNonce());
      }
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard?.writeText(text);
  };

  const tabs = [
    {
      id: 'aes',
      label: 'AES',
      title: 'Advanced Encryption Standard',
      description: 'AES is a symmetric encryption algorithm that uses the same key for both encryption and decryption. It is fast, secure, and widely used in applications requiring high-speed encryption of large amounts of data.',
      icon: '🔐'
    },
    {
      id: 'rsa',
      label: 'RSA',
      title: 'Rivest-Shamir-Adleman',
      description: 'RSA is an asymmetric encryption algorithm that uses a pair of keys - a public key for encryption and a private key for decryption. This allows secure communication without prior key exchange.',
      icon: '🔑'
    },
    {
      id: 'curve25519',
      label: 'Curve25519',
      title: 'Elliptic Curve Cryptography',
      description: 'Curve25519 is a modern elliptic curve designed for high security and performance. It provides the same security as RSA with much smaller key sizes and faster computations.',
      icon: '🌊'
    },
    {
      id: 'chacha20',
      label: 'ChaCha20',
      title: 'ChaCha20 Stream Cipher',
      description: 'ChaCha20 is a high-speed stream cipher designed by Daniel J. Bernstein. It provides strong security while being resistant to timing attacks and optimized for software implementations.',
      icon: '⚡'
    }
  ];

  const currentTab = tabs.find(tab => tab.id === activeTab);

  return (
    <section id="crypto-tool" className="py-20 bg-gray-800/50">
      <div className="container mx-auto px-4 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-4">
            Crypto <span className="bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent">Tool</span>
          </h2>
          <div className="w-24 h-1 bg-gradient-to-r from-blue-400 to-purple-500 mx-auto mb-8"></div>
          <p className="text-lg text-gray-400 max-w-3xl mx-auto">
            Encrypt and decrypt text using AES, RSA, Curve25519, and ChaCha20 algorithms. Perfect for learning cryptography basics.
          </p>
        </div>

        <div className="max-w-6xl mx-auto">
          {/* Algorithm Tabs */}
          <div className="flex flex-wrap justify-center gap-4 mb-8">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setInputText('');
                  setOutputText('');
                }}
                className={`flex items-center gap-3 px-6 py-4 rounded-xl font-medium transition-all duration-300 ${
                  activeTab === tab.id
                    ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg scale-105'
                    : 'bg-gray-800/50 text-gray-300 hover:bg-gray-700 hover:text-white border border-gray-600'
                }`}
              >
                <span className="text-2xl">{tab.icon}</span>
                <div className="text-left">
                  <div className="font-semibold">{tab.label}</div>
                  <div className="text-xs opacity-75">{tab.title}</div>
                </div>
              </button>
            ))}
          </div>

          {/* Algorithm Description */}
          <div className="text-center mb-8">
            <div className="bg-gray-900/50 backdrop-blur-sm border border-gray-700 rounded-xl p-6 max-w-4xl mx-auto">
              <div className="text-4xl mb-3">{currentTab?.icon}</div>
              <h3 className="text-2xl font-semibold text-white mb-2">{currentTab?.title}</h3>
              <p className="text-gray-400 leading-relaxed">{currentTab?.description}</p>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Input Section */}
            <div className="space-y-6">
              <div className="bg-gray-900/30 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                  <svg className="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                  </svg>
                  Input Text
                </h3>
                <textarea
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  placeholder="Enter text to encrypt/decrypt..."
                  className="w-full h-32 px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 focus:ring-1 focus:ring-blue-400 transition-all duration-300 resize-none"
                />
              </div>

              {/* Key Management */}
              <div className="bg-gray-900/30 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                    <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m0 0a2 2 0 012 2 2 2 0 002-2m-6 0a2 2 0 00-2-2 2 2 0 00-2 2 2 2 0 002 2 2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10a2 2 0 01-2 2H9a2 2 0 01-2-2V9z" />
                    </svg>
                    {activeTab === 'rsa' ? 'Key Pair' : activeTab === 'chacha20' ? 'Key & Nonce' : 'Secret Key'}
                  </h3>
                  <button
                    onClick={handleGenerateKeys}
                    className="px-4 py-2 bg-gradient-to-r from-green-500 to-teal-600 text-white text-sm font-medium rounded-lg hover:scale-105 transition-all duration-300"
                  >
                    Generate
                  </button>
                </div>

                {activeTab === 'rsa' ? (
                  <div className="space-y-4">
                    <div>
                      <label className="block text-gray-400 text-sm font-medium mb-2">Public Key (for encryption)</label>
                      <div className="relative">
                        <input
                          type="text"
                          value={publicKey}
                          onChange={(e) => setPublicKey(e.target.value)}
                          placeholder="Public key for encryption..."
                          className="w-full px-4 py-3 pr-10 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 transition-all duration-300"
                        />
                        <button
                          onClick={() => copyToClipboard(publicKey)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors duration-300"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-gray-400 text-sm font-medium mb-2">Private Key (for decryption)</label>
                      <div className="relative">
                        <input
                          type="text"
                          value={privateKey}
                          onChange={(e) => setPrivateKey(e.target.value)}
                          placeholder="Private key for decryption..."
                          className="w-full px-4 py-3 pr-10 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400 transition-all duration-300"
                        />
                        <button
                          onClick={() => copyToClipboard(privateKey)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors duration-300"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                ) : activeTab === 'chacha20' ? (
                  <div className="space-y-4">
                    <div>
                      <label className="block text-gray-400 text-sm font-medium mb-2">Secret Key (256-bit)</label>
                      <div className="relative">
                        <input
                          type="text"
                          value={secretKey}
                          onChange={(e) => setSecretKey(e.target.value)}
                          placeholder="32-byte secret key..."
                          className="w-full px-4 py-3 pr-10 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 transition-all duration-300"
                        />
                        <button
                          onClick={() => copyToClipboard(secretKey)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors duration-300"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                    <div>
                      <label className="block text-gray-400 text-sm font-medium mb-2">Nonce (96-bit)</label>
                      <div className="relative">
                        <input
                          type="text"
                          value={nonce}
                          onChange={(e) => setNonce(e.target.value)}
                          placeholder="12-byte nonce for stream cipher..."
                          className="w-full px-4 py-3 pr-10 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400 transition-all duration-300"
                        />
                        <button
                          onClick={() => copyToClipboard(nonce)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors duration-300"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="relative">
                    <label className="block text-gray-400 text-sm font-medium mb-2">Secret Key</label>
                    <input
                      type="text"
                      value={secretKey}
                      onChange={(e) => setSecretKey(e.target.value)}
                      placeholder="Secret key for encryption/decryption..."
                      className="w-full px-4 py-3 pr-10 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 transition-all duration-300"
                    />
                    <button
                      onClick={() => copyToClipboard(secretKey)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors duration-300"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                )}
              </div>

              {/* Action Buttons */}
              <div className="flex gap-4">
                <button
                  onClick={handleEncrypt}
                  disabled={isLoading || !inputText || (activeTab === 'rsa' ? !publicKey : activeTab === 'chacha20' ? (!secretKey || !nonce) : !secretKey)}
                  className="flex-1 flex items-center justify-center gap-2 px-6 py-4 bg-gradient-to-r from-blue-500 to-blue-600 text-white font-semibold rounded-xl hover:scale-105 hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none transition-all duration-300"
                >
                  {isLoading ? (
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                  )}
                  Encrypt
                </button>
                <button
                  onClick={handleDecrypt}
                  disabled={isLoading || !inputText || (activeTab === 'rsa' ? !privateKey : activeTab === 'chacha20' ? (!secretKey || !nonce) : !secretKey)}
                  className="flex-1 flex items-center justify-center gap-2 px-6 py-4 bg-gradient-to-r from-purple-500 to-purple-600 text-white font-semibold rounded-xl hover:scale-105 hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none transition-all duration-300"
                >
                  {isLoading ? (
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                  ) : (
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
                    </svg>
                  )}
                  Decrypt
                </button>
              </div>
            </div>

            {/* Output Section */}
            <div className="space-y-6">
              <div className="bg-gray-900/30 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                    <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Output
                  </h3>
                  {outputText && (
                    <button
                      onClick={() => copyToClipboard(outputText)}
                      className="px-4 py-2 bg-gray-700 text-gray-300 text-sm font-medium rounded-lg hover:bg-gray-600 hover:text-white transition-all duration-300"
                    >
                      Copy
                    </button>
                  )}
                </div>
                <div className="relative">
                  <textarea
                    value={outputText}
                    readOnly
                    placeholder="Result will appear here..."
                    className="w-full h-32 px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 resize-none cursor-default"
                  />
                </div>
              </div>

              {/* Security Notice */}
              <div className="bg-amber-900/20 border border-amber-600 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <svg className="w-6 h-6 text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                  <h4 className="text-lg font-semibold text-amber-400">Security Notice</h4>
                </div>
                <p className="text-amber-200 text-sm leading-relaxed">
                  This tool is for educational purposes only. The implementations are simplified demonstrations and 
                  not cryptographically secure. Never use these algorithms for real-world security applications.
                </p>
              </div>

              {/* Algorithm Details */}
              <div className="bg-gray-900/30 backdrop-blur-sm border border-gray-700 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-white mb-3">About {currentTab?.label}</h4>
                <div className="text-gray-300 text-sm space-y-2">
                  {activeTab === 'aes' && (
                    <>
                      <p>• <strong>Type:</strong> Symmetric encryption algorithm</p>
                      <p>• <strong>Key Size:</strong> 128, 192, or 256 bits</p>
                      <p>• <strong>Use Case:</strong> Fast encryption of large data sets</p>
                      <p>• <strong>Security:</strong> Widely trusted and standardized</p>
                    </>
                  )}
                  {activeTab === 'rsa' && (
                    <>
                      <p>• <strong>Type:</strong> Asymmetric encryption algorithm</p>
                      <p>• <strong>Key Size:</strong> Typically 2048 or 4096 bits</p>
                      <p>• <strong>Use Case:</strong> Secure key exchange and digital signatures</p>
                      <p>• <strong>Security:</strong> Based on factoring large prime numbers</p>
                    </>
                  )}
                  {activeTab === 'curve25519' && (
                    <>
                      <p>• <strong>Type:</strong> Elliptic curve cryptography</p>
                      <p>• <strong>Key Size:</strong> 255 bits (equivalent to 3072-bit RSA)</p>
                      <p>• <strong>Use Case:</strong> Modern protocols and key agreement</p>
                      <p>• <strong>Security:</strong> Resistant to side-channel attacks</p>
                    </>
                  )}
                  {activeTab === 'chacha20' && (
                    <>
                      <p>• <strong>Type:</strong> Stream cipher</p>
                      <p>• <strong>Key Size:</strong> 256 bits with 96-bit nonce</p>
                      <p>• <strong>Use Case:</strong> High-speed encryption, mobile devices</p>
                      <p>• <strong>Security:</strong> Resistant to timing attacks</p>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

window.CryptoTool = CryptoTool;