<%
rebase('base.tpl', title='Supporting sites', open_graph=True,
       description='The list of sites that are known to support Global Privacy Control.')
%>
<main>
  <span class="spacer"></span>
  <div class="content">
    <h2>Supporting Sites</h2>
    <div class="section">
      <div class="linkList">
        % for domain in domains:
        <a href="/sites/{{domain}}">{{domain}}</a>
        % end
      </div>
    </div>
    <div class="section">
      <div class="linkRow">
        % if previous_page is not None:
        %   if previous_page == 0:
        <a href="/sites/">Previous</a>
        %   else:
        <a href="/sites/?page={{previous_page}}">Previous</a>
        %   end
        % else:
        <a class="disabled">Previous</a>
        % end
        <span class="spacer"></span>
        % if next_page is not None:
        <a href="/sites/?page={{next_page}}">Next</a>
        % else:
        <a class="disabled">Next</a>
        % end
      </div>
      <div class="linkRow">
        <a href="/">Home</a>
      </div>
    </div>
  </div>
  <span class="spacer"></span>
</main>
