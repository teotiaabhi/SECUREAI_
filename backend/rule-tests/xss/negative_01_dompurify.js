/**
 * Test:     negative_01_dompurify
 * Expected: NO TRIGGER (safe)
 * Category: XSS
 * Language: JavaScript (React)
 *
 * Description:
 *   React component that properly sanitizes user input with
 *   DOMPurify before passing it to dangerouslySetInnerHTML.
 *   This is the accepted safe pattern and must NOT trigger
 *   any XSS rules.
 */

import React, { useState, useEffect } from 'react';
import DOMPurify from 'dompurify';

function SafeUserProfileCard() {
  const [profileBio, setProfileBio] = useState('');
  const [userName, setUserName] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const bioParam = params.get('bio') || '';
    const nameParam = params.get('name') || '';

    // SAFE: Sanitize all user-controlled inputs before storing
    setProfileBio(DOMPurify.sanitize(bioParam));
    setUserName(DOMPurify.sanitize(nameParam, { ALLOWED_TAGS: [] }));
  }, []);

  const createSanitizedMarkup = () => {
    // SAFE: Content is already sanitized via DOMPurify
    return { __html: profileBio };
  };

  return (
    <div className="profile-card">
      <h2 className="profile-name">{userName}</h2>
      <div className="profile-bio-section">
        <h3>About Me</h3>
        {/* SAFE: dangerouslySetInnerHTML with DOMPurify-sanitized content */}
        <div
          className="profile-bio"
          dangerouslySetInnerHTML={createSanitizedMarkup()}
        />
      </div>
      <div className="profile-actions">
        <button onClick={() => navigator.clipboard.writeText(window.location.href)}>
          Share Profile
        </button>
      </div>
    </div>
  );
}

export default SafeUserProfileCard;
