<%
rebase('base.tpl', title='Check a site', open_graph=True,
       description='Check if a site supports Global Privacy Control.')
%>
<div class="content">
  <main>
    <h1>GPC<br>SUP</h1>
    <div class="section">
      <p>
        Check if a site supports<br>
        <a href="https://globalprivacycontrol.org" target="_blank" rel="noopener noreferrer">
          Global Privacy Control
        </a>
      </p>
      <p>
        Supporting sites are tweeted by
        <a href="https://twitter.com/gpcsup" target="_blank" rel="noopener noreferrer">
          @gpcsup
        </a>
      </p>
    </div>
    <form action="/" method="POST">
      % if defined('domain') and domain:
      <input type="text" name="domain" placeholder="Domain Name" value="{{domain}}" required>
      % else:
      <input type="text" name="domain" placeholder="Domain Name" required>
      % end
      <button class="mainButton">Check Site</button>
    </form>
  </main>
  % if supporting_count:
  <footer>
    <p>{{ f'{scanned_count:,}' }} sites scanned</p>
    <a href="{{well_known_search}}" target="_blank" rel="noopener noreferrer">{{ f'{supporting_count:,}' }} supporting sites found</a>
  </footer>
  % end
</div>
