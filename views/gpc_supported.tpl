<%
rebase('base.tpl', title=f'GPC supported by {domain}', open_graph=True,
       description=f'Global Privacy Control is supported by {domain}.')
%>
<main>
  <span class="spacer"></span>
  <div class="content">
    <div class="section">
      <svg class="bigIcon supported" width="200" height="200" viewBox="0 0 24 24" stroke="currentColor" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a><br>
        is supported by<br>
        <a href="https://{{domain}}" target="_blank" rel="noopener noreferrer">
          {{domain}}
        </a>
      </p>
      % if defined('message') and message:
      <p>
        However, the GPC support resource doesn't follow the
        <a href="https://globalprivacycontrol.github.io/gpc-spec/#gpc-support-resource"
           target="_blank" rel="noopener noreferrer">spec</a>
        exactly -
        {{message}}
      </p>
      % end
    </div>
    <div class="section">
      <div class="linkRow">
        <a href="/">Check Another</a>
      </div>
    </div>
  </div>
  <span class="spacer"></span>
</main>
