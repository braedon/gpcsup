<%
rebase('base.tpl', title='Check a site', open_graph=True,
       description='Check if a site supports Global Privacy Control.')
%>
<main>
  <span class="spacer"></span>
  <div class="content">
    <h1>GPC<br>SUP</h1>
    <div class="section">
      <p>
        Check if a site supports<br>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a>
      </p>
    </div>
    <form class="section" action="/" method="POST">
      % if defined('domain') and domain:
      <input type="text" name="domain" placeholder="Domain Name" value="{{domain}}" required>
      % else:
      <input type="text" name="domain" placeholder="Domain Name" required>
      % end
      <button class="mainButton">Check Site</button>
    </form>
    <div class="section">
      <div class="linkRow">
        <a href="/sites/">Supporting Sites</a>
      </div>
    </div>
  </div>
  <span class="spacer"></span>
</main>
