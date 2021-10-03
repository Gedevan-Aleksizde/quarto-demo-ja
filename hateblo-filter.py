#! /usr/bin/env python

# from pandocfilters import toJSONFilter, Emph, Para
import argparse
import os
import sys
import warnings
from pathlib import Path
import json
import panflute as pf
from collections import OrderedDict
import re

import requests
import base64
import hashlib
from datetime import datetime
import random
import mimetypes
from xml.etree import ElementTree

# これを参考にした
# https://www.lisz-works.com/entry/python3-fotolife-upload

class hatena_token():
  def __init__(self, HATENA_USER, HATENA_BLOG, FOTO_API_KEY, FOTO_FOLDER='Hatena Blog'):
    self.hatena_user = HATENA_USER
    self.hatena_blog = HATENA_BLOG
    self.foto_api_key = FOTO_API_KEY
    self.foto_folder = FOTO_FOLDER
    self.endpoint_photo = 'https://f.hatena.ne.jp/atom/post/'
    self.endpoint_blog = f'https://blog.hatena.ne.jp/{self.hatena_user}/{self.hatena_blog}/atom'
  
  def _wsse(self, hatena_user=None, foto_api_key=None):
    if not hatena_user:
      hatena_user = self.hatena_user
    if not foto_api_key:
      foto_api_key = self.foto_api_key
    created_at = datetime.now().isoformat() + "Z"
    b_nonce = hashlib.sha1(str(random.random()).encode()).digest()
    b_digest = hashlib.sha1(b_nonce + created_at.encode() + foto_api_key.encode()).digest()
    return 'UsernameToken Username="{}", PasswordDigest="{}", Nonce="{}", Created="{}"'.format(
      hatena_user,
      base64.b64encode(b_digest).decode(),
      base64.b64encode(b_nonce).decode(),
      created_at)
  
  def _create_image_xml(self, file_name_path, title='', to_folder=None):
    if not to_folder:
      to_folder = self.foto_folder if self.foto_folder else 'Hatena Blog'
    content_type = mimetypes.guess_type(file_name_path)[0]
    uploadData = base64.b64encode(file_name_path.read_bytes())
    return f"""
    <entry xmlns="http://purl.org/atom/ns#">
    <title>{title}</title>
    <content type="{content_type}" mode="base64">""" + uploadData.decode() + f"""</content>
    <dc:subject>{to_folder}</dc:subject>
    </entry>
    """

  def post_hatenaphoto(self, file_name, title='', to_folder=None, *args):
    file_name_path = Path(file_name)
    r = requests.post(self.endpoint_photo, data=self._create_image_xml(file_name_path, title, to_folder), headers={'X-WSSE': self._wsse(*args)})
    try:
        r.raise_for_status()
    except:
        raise requests.exceptions.RequestException(f'Error!\nstatus_code: {r.status_code}\nmessage: {r.text}')
    self.last_result = r
    return self

def filter_hatena_toc(elem, doc):
  """
  目次を挿入する場合ははてな記法で自動生成するように置き換え
  """
  if isinstance(elem, pf.RawBlock):
    if elem.format == 'latex' and elem.text == r'\tableofcontents{}':
      return pf.Plain(pf.RawInline('[:contents]'))

def filter_hatena_header_level(elem, doc):
  """
  見出しの最高レベルを <h2> タグに
  """
  if isinstance(elem, pf.Header):
    elem.level += 1

def filter_hatena_link(elem, doc):
  """
  ハイパーリンクをはてな記法に置き換え
  """
  if isinstance(elem, pf.Link):
    if elem.url[0] != '#':
      url_title = pf.stringify(elem).strip()
      if url_title == ':title:':
        return pf.RawInline('[{}:title]'.format(elem.url))
      if url_title == ':embed:':
        return pf.RawInline('[{}:embed:title]'.format(elem.url))
      elif url_title == '':
        return pf.RawInline('[{}]'.format(elem.url))
      else:
        return pf.RawInline('[{0}:title={1}]'.format(elem.url, url_title))

def filter_hatena_footnote(elem, doc):
  """
  脚注をはてな記法に置き換え. <code> が含まれていると機能しないので平文に変換する.
  """
  if isinstance(elem, pf.Note):
    content_without_code = [pf.Str(f'`{pf.stringify(x)}`') if isinstance(x, pf.Code) else x for x in elem.content[0].content]
    return [pf.Str('((')] + content_without_code + [pf.Str('))')]

def filter_hatena_mathjax(elem, doc):
  if isinstance(elem, pf.Math):
    math_expr = elem.text
    math_expr = re.sub('^\\\\begin{aligned}', r'\\begin{align}', math_expr)
    math_expr = re.sub('\\\\end{aligned}', r'\\end{align}', math_expr)
    math_code = pf.RawInline('[tex: {}]'.format(math_expr))
    if elem.format == 'DisplayMath':
      return [pf.RawInline('\n'), pf.Span(math_code, classes=['Math', 'DisplayMath']), pf.RawInline('\n')]
    elif elem.format == 'InlineMath':
      return math_code

def filter_hatena_blockquote(elem, doc):
  if isinstance(elem, pf.BlockQuote):
    quotecomponents = [pf.RawInline('>>'), pf.RawInline('\n')] + list(elem.content[0].content) + [pf.RawInline('\n'), pf.RawInline('<<')]
    return pf.Plain(*quotecomponents)
  elif isinstance(elem, pf.Div) and 'epigraph' in elem.classes:
    epigraph_phrase = elem.content[0]
    epigraph_source = elem.content[1]
    return pf.Plain(*[pf.RawInline(f'>')] + list(epigraph_source.content) + [pf.RawInline('>'), pf.RawInline('\n')] + list(epigraph_phrase.content) + [pf.RawInline('\n'), pf.RawInline('<<')])

def filter_hatena_codeblock(elem, doc):
  if isinstance(elem, pf.CodeBlock):
    # TODO: デフォルト言語をどこで読み取るか
    lang = elem.attributes.get('language')
    return pf.RawBlock('>|{lang}|\n{code}\n||<'.format(code=elem.text, lang=lang if lang else ''))

def filter_hatena_image(elem, doc):
  """
  pandoc-crossref のタグを消したりはてなフォトライフにアップロードしたりはてな記法に置換したり
  """
  enable_upload = doc.get_metadata('enable-upload')
  if not enable_upload:
    enable_upload = False

  if isinstance(elem, pf.Image):
    if enable_upload:
      settings_local = Path().cwd().joinpath('settings.json')
      settings_root = Path(__file__).resolve().parent.parent.joinpath('settings/settings.json')
      warnings.warn(settings_local)
      warnings.warn(settings_root)
      if settings_local.exists():
        path_settings = settings_local
      elif settings_root.exists():
        path_settings = settings_root
      else:
         path_settings = None
      if path_settings is not None:
        with settings_root.open('r') as f:
          params_hatenaapi = json.load(f)
      else:
        params_hatenaapi = {k: os.environ.get(k) for k in ('FOTO_API_KEY', 'HATENA_USER', 'HATENA_BLOG')}
      for k in ('FOTO_API_KEY', 'HATENA_USER', 'HATENA_BLOG'):
        if params_hatenaapi.get(k) is None:
          raise KeyError(f'API Parameter `{k}` not found in the settings.')
      uploader = hatena_token(**params_hatenaapi)
      uploader.post_hatenaphoto(elem.url)
      res = ElementTree.fromstring(uploader.last_result.text)
      image_file_id = ':'.join(res.find('hatena:syntax', {'hatena': 'http://www.hatena.ne.jp/info/xmlns#'}).text.split(':')[2:-1])
      image_file_id = f'[f:id:{image_file_id}:plain]'  # TODO: 画像サイズ調整
    else:
      image_file_id = 'INSERT_FILE_ID_HERE'
    ref_ids_img = [x.identifier for x in elem.content if hasattr(x, 'identifier') and x.identifier[:4] == 'fig:']
    if len(ref_ids_img) > 0:  # TODO: 複数ID存在するケースってあるの
      caption_inlines = [x for x in elem.content if isinstance(x, pf.Inline)]
      caption_inlines = [x for x in caption_inlines if not (hasattr(x, 'attributes') and x.attributes.get('label'))]
      caption_plain = str(pf.stringify(pf.Span(*caption_inlines)))
      return [
        pf.RawInline('\n'), pf.RawInline(f'><figure class="figure-image figure-image-fotolife" title="{caption_plain}"><figcaption id="{ref_ids_img[0]}">')
        ] + caption_inlines + [pf.RawInline(f'</figcaption>{image_file_id}</figure><'), pf.RawInline('\n')]
    else:
      return pf.RawInline(image_file_id)

def filter_table_remove_tag(elem, doc):
  """
  pandoc-crossref が残すタグを消す
  """
  if isinstance(elem, pf.Table):
    ref_ids_tab = [x.identifier for x in elem.caption if hasattr(x, 'identifier') and x.identifier[:4] == 'tab:']
    if len(ref_ids_tab) > 0:
      tab_caption_inlines = [x for x in elem.caption if isinstance(x, pf.Inline)]
      tab_caption_inlines = [x for x in tab_caption_inlines if not (hasattr(x, 'attributes') and x.attributes.get('label'))]
      elem.caption = tab_caption_inlines
      return elem

def filter_eqref(elem, doc):
  """
  [eq:...] の参照タグを MathJax 参照に置き換える
  """
  if isinstance(elem, pf.Link) and elem.url[:4] == '#eq:':
    ref_id_eq = elem.url[1:]
    return pf.Span(pf.RawInline('(\\ref{' + ref_id_eq + '})'), attributes={'data-reference-type': 'ref', 'data-reference': f'{ref_id_eq}'})

if __name__ == '__main__':
    pf.run_filters(actions=[
      filter_hatena_toc,
      filter_hatena_header_level,
      filter_hatena_link,
      # filter_hatena_footnote,
      filter_hatena_mathjax,
      filter_hatena_blockquote,
      filter_hatena_codeblock,
      # filter_hatena_image,
      # filter_table_remove_tag,
      filter_eqref
    ], doc=None)
