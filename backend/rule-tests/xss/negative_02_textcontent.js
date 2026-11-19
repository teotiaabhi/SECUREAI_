// Test: negative for rule XSS-JS-001, XSS-JS-002
// Expected: should_not_trigger
// Category: xss
// Language: javascript

/**
 * Safe DOM manipulation example using textContent and innerText
 * instead of innerHTML or document.write.
 */

function encodeForAttribute(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function getQueryParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name) || '';
}

function renderUserProfile() {
    const username = getQueryParam('username');
    const bio = getQueryParam('bio');
    const role = getQueryParam('role');

    const nameEl = document.getElementById('profile-name');
    const bioEl = document.getElementById('profile-bio');
    const roleEl = document.querySelector('.role-badge');

    if (nameEl) {
        nameEl.textContent = username;
    }

    if (bioEl) {
        bioEl.innerText = bio;
    }

    if (roleEl) {
        roleEl.textContent = role || 'Member';
    }
}

document.addEventListener('DOMContentLoaded', function () {
    renderUserProfile();

    const searchInput = document.getElementById('search-input');
    const searchOutput = document.getElementById('search-results-label');

    if (searchInput && searchOutput) {
        searchInput.addEventListener('input', function (event) {
            const query = event.target.value;
            searchOutput.textContent = 'Showing results for: ' + query;
        });
    }

    const form = document.getElementById('comment-form');
    if (form) {
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            const commentText = form.elements['comment'].value;
            const commentEl = document.createElement('p');
            commentEl.textContent = commentText;
            document.getElementById('comments-list').appendChild(commentEl);
        });
    }
});
