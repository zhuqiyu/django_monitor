# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.test import TestCase

# Create your tests here.

import os
import random
import io
import string
import sys
import math
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from django.conf import settings



class authCode(object):

    def __init__(self):

        # 字体的位置，不同版本的系统会有不同,字体为微软雅黑
        self.font_path = os.path.join(settings.STATICFILES_DIRS[0], "fonts/MSYH.TTC")
        # print font_path
        # 生成几位数的验证码
        self.number = 4
        # 生成验证码图片的高度和宽度
        self.size = (100, 30)
        # 背景颜色，默认为白色
        self.bgcolor = (255, 255, 255)
        # 字体颜色，默认为蓝色
        self.fontcolor_list = [(0, 0, 255), (0, 255, 0), (0, 0, 0)]
        temp_int = random.randint(0, 2)
        if temp_int == 1:
            self.color = u'绿色'
            self.fontcolor = self.fontcolor_list[temp_int]
        elif temp_int == 2:
            self.color = u'黑色'
            self.fontcolor = self.fontcolor_list[temp_int]
        else:
            self.color = u'蓝色'
            self.fontcolor = self.fontcolor_list[temp_int]
        # 干扰线颜色。默认为红色
        self.linecolor_list = [(255, 0, 255), (255, 255, 0), (144, 238, 144)]
        self.linecolor = self.linecolor_list[temp_int]
        # 是否要加入干扰线
        self.draw_line = True
        # 加入干扰线条数的上下限
        self.line_number = (5, 10)

        # 用来随机生成一个字符串
        # source = list(string.ascii_lowercase+'1234567890')
        self.source = list('1234567890')

    def gene_text(self):
        #     return '6666'
        return ''.join(random.sample(self.source, self.number))  # number是生成验证码的位数

    # 用来绘制干扰线
    def gene_line(self):
        width = 38  # 宽和高
        height = 30
        print(type(self.font_path))
        print(self.font_path)
        font = ImageFont.truetype(self.font_path, 25)  # 验证码的字体
        draw = ImageDraw.Draw(self.image)  # 创建画笔
        text = ''.join(random.sample(self.source, 3))  # 生成字符串
        font_width, font_height = font.getsize(text)
        draw.text(((width - font_width) / 10, (height - font_height) / 10), text,
                  font=font, fill=self.linecolor)  # 填充字符串

    # 生成颜色图片
    def create_color(self):
        height = 18  # 宽和高
        width = 30
        image2 = Image.new('RGBA', (width, height), self.bgcolor)  # 创建图片
        font = ImageFont.truetype(self.font_path, 15)  # 验证码的字体
        draw = ImageDraw.Draw(image2)  # 创建画笔
        font_width, font_height = font.getsize(self.text)
        draw.text(((width - font_width) / self.number, (height - font_height) / self.number), self.color,
                  font=font, fill=self.fontcolor)  # 填充字符串
        buf2 = io.BytesIO()  # io.BytesIO() #io.StringIO() use it to fill str obj
        image2.save(buf2, 'png')
        return buf2.getvalue(), 'image/png'

    # 生成验证码
    def gene_code(self):
        width, height = self.size  # 宽和高
        self.image = Image.new('RGBA', (width, height), self.bgcolor)  # 创建图片
        print(type(self.font_path))
        print(self.font_path)
        font = ImageFont.truetype(self.font_path, 25)  # 验证码的字体
        draw = ImageDraw.Draw(self.image)  # 创建画笔
        self.text = self.gene_text()  # 生成字符串
        font_width, font_height = font.getsize(self.text)
        draw.text(((width - font_width) / self.number, (height - font_height) / self.number), self.text,
                  font=font, fill=self.fontcolor)  # 填充字符串
        if self.draw_line:
            self.gene_line()
        self.image = self.image.transform((width + 20, height + 10), Image.AFFINE, (1, -0.3, 0, -0.1, 1, 0), Image.BILINEAR)  # 创建扭曲
        self.image = self.image.filter(ImageFilter.EDGE_ENHANCE_MORE)  # 滤镜，边界加强

    #image_file = text + '.png'

    #image_path = os.path.join(settings.STATIC_ROOT, 'images/%s' % image_file)

    #image.save(image_path)  # 保存验证码图片

    #return 'http://login.*.net:8000/static/images/%s' % image_file, text

        buf = io.BytesIO()  # io.BytesIO() #io.StringIO() use it to fill str obj
        self.image.save(buf, 'png')
        # request.session['captcha'] = text.lower()

        # return HttpResponse(buf.getvalue(), 'image/png')
        return (buf.getvalue(),'image/png')


if __name__ == "__main__":
    print()
