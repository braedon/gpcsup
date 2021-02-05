<%
rebase('base.tpl', title=f'GPC not supported by {domain}', open_graph=True,
       description=f'Global Privacy Control is not supported by {domain}.')
%>
<div class="content">
  <main>
    <div class="section">
      <svg class="bigIcon unsupported" width="200" height="200" viewBox="0 0 24 24" stroke="currentColor" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a><br>
        is not supported by<br>
        <a href="https://{{domain}}"
           target="_blank" rel="noopener noreferrer">
          {{domain}}
        </a>
      </p>
      % if defined('message') and message:
      <p>
        {{message}}
      </p>
      % end
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
