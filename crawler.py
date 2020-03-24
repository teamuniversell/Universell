from parser import HtmlParser
from urllib.parse import urlparse,urlencode

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin


class Crawler(object):

    def __init__(self, seedurl):
        self.seedurl = seedurl
        self.urlseen = set()  # store URLs
        self.user_output = []

        # parse seed url to get domain.
        # crawler does not support external domain.
        urlparsed = urlparse(seedurl)
        self.domain = urlparsed.netloc

    def get_links(self, html):
        """
        Parse return link in html contents
        by finding href attribute in a tag.
        """

        hrefs = set()
        parser = HtmlParser(html)

        # get href tags from parsed results
        for href in parser.hrefs:
            u_parse = urlparse(href)

            # check whether href content is same domain with seed url
            if u_parse.netloc == '' or u_parse.netloc == self.domain:
                hrefs.add(href)
        return hrefs

    def fetch(self, url):
        """
        return fetch HTML content from url
        return empty string if response raise an HTTPError (not found, 500...)
        """

        try:
            # urllib.parse.
            
            req = Request(url)
            req.add_header("User-Agent","Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0")
            res = urlopen(req)
            return res.read().decode('utf-8', 'ignore')

        except HTTPError as e:
            print('ERROR: %s \t  %s' % (url, e.code))
            return ''
        except URLError as e:
            print('Reason: ', e.reason)
            return ''
        except Exception as e:
            return ''
        

    def crawl(self):
        # add seed url to url frontier
        # URL frontier is the list which stores found URL but not yet crawled.
        # it works like a queue.
        url_frontier = list()
        url_frontier.append(self.seedurl)

        while url_frontier:
            url = url_frontier.pop()  # get url from frontier

            # do not crawl twice the same page
            if url not in self.urlseen:
                html = self.fetch(url)

                if html:  # if reponse has html content
                    print('Crawl: ', url)
                    self.user_output.append('Crawl: ' + url)
                    self.urlseen.add(url)

                for href in self.get_links(html):
                    # join seed url and href, to get url
                    joinlink = urljoin(self.seedurl, href)
                    # print("joing href >> ", joinlink)  # uncomment this line to understand
                    first = ".pdf" not in joinlink
                    sec = ".jpg" not in joinlink
                    thi = ".png" not in joinlink
                    four = ".doc" not in joinlink
                    fif = ".docx" not in joinlink
                    if( first and sec and thi and four and fif ):
                        url_frontier.append(joinlink)

    @property
    def crawled_urls(self):
        self.crawl()
        return self.urlseen



# seedurl = "http://sw.muet.edu.pk/"
# crawler = Crawler(seedurl)
# # crawler.crawl()
# for url in crawler.crawled_urls:
#     crawler.user_output.append(">>>" +url)
#     print('>>>', url)


# seedurl = "http://sw.muet.edu.pk/"
# crawler = Crawler(seedurl)
# crawler.crawl()
# for url in crawler.crawled_urls:
#     crawler.user_output.append(">>>" +url)

# for link in crawler.user_output:
#     print(link)
