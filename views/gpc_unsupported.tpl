<%
rebase('base.tpl', title=f'GPC not supported by {domain}',
       open_graph=True, open_graph_image='gpc_unsupported.png',
       description=f'Global Privacy Control is not supported by {domain}.',
       post_scripts=['gpc_res'])
%>
<div class="content">
  <main>
    <div class="section">
      <svg class="bigIcon unsupported" width="200" height="200" viewBox="0 0 24 24" stroke="currentColor" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>
        <a href="{{scheme}}://{{domain}}" target="_blank" rel="noopener noreferrer nofollow">
          {{domain}}
        </a><br>
        reports that it does not support<br>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a>
      </p>
      <p>Last Update: {{last_update or 'Unspecified'}}</p>
      % if defined('message') and message:
      <p>
        However, its GPC support resource doesn't follow the
        <a href="https://globalprivacycontrol.github.io/gpc-spec/#gpc-support-resource"
           target="_blank" rel="noopener noreferrer">spec</a>
        exactly -
        {{message}}
      </p>
      % end
      <p class="subInfo">
        % from rfc3339 import datetimetostr
        Checked <span id="updateDateTime">{{datetimetostr(scan_dt)}}</span>
      </p>
      % if rescan_queued:
      <p>Recheck queued.</p>
      % elif can_rescan:
      <form action="/" method="POST">
        <input type="hidden" name="domain" value="{{domain}}">
        <button>Recheck</button>
      </form>
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
