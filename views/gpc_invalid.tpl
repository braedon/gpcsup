% rebase('base.tpl', title=f'Invalid domain', no_index=True)
<div class="content">
  <main>
    <div class="section">
      <svg class="bigIcon error" width="200" height="200" viewBox="0 0 24 24" stroke="currentColor" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>
        % if defined('domain') and domain:
        {{domain}}<br>
        % else:
        That
        % end
        isn't a valid domain.
      </p>
    </div>
  </main>
  <footer>
    <div class="section">
      <div class="linkRow">
        <a href="/">Check Another Site</a>
      </div>
    </div>
  </footer>
</div>
