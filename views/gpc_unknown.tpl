<%
rebase('base.tpl', title=f'GPC support unknown for {domain}',
       open_graph=True, open_graph_image='gpc_unknown.png',
       description=f'Global Privacy Control support is not reported by {domain}.',
       post_scripts=['gpc_res'])
%>
<div class="content">
  <main>
    <div class="section">
      <svg class="bigIcon unknown" width="200" height="200" viewBox="0 0 24 24" stroke="currentColor" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <p>
        <a href="{{scheme}}://{{domain}}" target="_blank" rel="noopener noreferrer nofollow">
          {{domain}}
        </a><br>
        does not report whether it supports<br>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a>
      </p>
      % if defined('message') and message:
      <p>{{message}}</p>
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
