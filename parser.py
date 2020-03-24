from bs4 import BeautifulSoup


class HtmlParser(object):

    def __init__(self, html):
        self.soup = BeautifulSoup(html, 'html5lib')

    @property
    def hrefs(self):
        # find all a tag which contains href attribute
        a_tags = self.soup.find_all("a", {"href": True})
        for tag in a_tags:
            yield tag['href']

    @property
    def script_text(self):
        # find all script tag
        # return a list of text content in <script> tag.
        # for example: <script>alert(1)</script>
        # will return alert(1)
        scripts = self.soup.find_all('script')
        return [script.text for script in scripts]
