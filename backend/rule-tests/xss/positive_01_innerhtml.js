/**
 * Test:     positive_01_innerhtml
 * Expected: TRIGGER XSS-JS-001, XSS-REACT-001
 * Category: XSS
 * Language: JavaScript (React)
 *
 * Description:
 *   React functional component that reads user input from URL query
 *   parameters and renders it using dangerouslySetInnerHTML without
 *   any sanitization. This is a textbook reflected XSS vector.
 */

import React, { useState, useEffect } from 'react';

function UserProfileCard() {
  const [profileBio, setProfileBio] = useState('');
  const [userName, setUserName] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const bioParam = params.get('bio') || '';
    const nameParam = params.get('name') || '';

    // VULNERABLE: User-controlled input assigned directly
    setProfileBio(bioParam);
    setUserName(nameParam);
  }, []);

  const renderBio = () => {
    // VULNERABLE: Unsanitized user input passed to dangerouslySetInnerHTML
    return { __html: profileBio };
  };

  return (
    <div className="profile-card">
      <h2 className="profile-name">{userName}</h2>
      <div className="profile-bio-section">
        <h3>About Me</h3>
        {/* VULNERABLE: dangerouslySetInnerHTML with raw user input */}
        <div
          className="profile-bio"
          dangerouslySetInnerHTML={renderBio()}
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

export default UserProfileCard;
