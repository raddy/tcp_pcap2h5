from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import numpy as np
import os,cython

sourcefiles = ['tcp_pcap2h5.pyx']
this_dir = os.path.split(cython.__file__)[0]
extensions = [
    Extension("tcp_pcap2h5", sourcefiles,
              library_dirs=['/glt/tools/libpcap-1.1.1/lib'],
              libraries=['pcap'],
              extra_compile_args=["-I/glt/tools/libpcap-1.1.1/include"],
              extra_link_args=["-L/glt/tools/libpcap-1.1.1/lib"],
              include_dirs=[np.get_include(),this_dir])
    ]

setup(cmdclass={'build_ext': build_ext},
      ext_modules=extensions,language="c++")

