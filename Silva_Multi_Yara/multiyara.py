
from volatility3.framework import renderers, interfaces, layers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.framework import exceptions
from volatility3.plugins.windows import pslist
from volatility3.plugins import yarascan
import sys
import os
from pathlib import Path
import pygit2

class MultiYara(interfaces.plugins.PluginInterface):

  _required_framework_version = (2, 0, 0)
  files = []
  folder = []
  root_system = os.path.abspath(os.path.sep)
  print(root_system)
  root_path = root_system + "yara/" 
  folders = ["rules/","Yara-rules/","malware-ioc/","signature-base/","ATR-Yara-Rules/"]
  repositoriesURL = ["https://github.com/Yara-Rules/rules.git","https://github.com/bartblaze/Yara-rules.git","https://github.com/eset/malware-ioc.git","https://github.com/Neo23x0/signature-base.git","https://github.com/advanced-threat-research/Yara-Rules.git"]
  custom_rules = "C:/custom_rules/" #Can be changed to whatever where you have your own rules


  @classmethod
  def get_requirements(cls):
    return [requirements.TranslationLayerRequirement(name = 'primary', description = 'Memory layer for the kernel', 
    architectures = ["Intel32", "Intel64"]), 
    requirements.PluginRequirement(name = 'yarascan', plugin = yarascan.YaraScan, version = (1, 0, 0)), 
    requirements.URIRequirement(name = "yara_file",description = "Yara rule (as a file)",optional = True),
    requirements.IntRequirement(name="rules",description="Number of files on the folder", default=1,optional=True),
    requirements.StringRequirement(name="category",description="categories for rules",default=False,optional=True),
    requirements.BooleanRequirement(name="clone", description="Clones all repositories",default=False, optional=True),
    requirements.BooleanRequirement(name="pull", description="Updates all repositories",default=False, optional=True)
    ]
  

  def run(self):
    if self.config['clone']:
      self.gitClone();
    if self.config['pull']:
      self.gitPull()
    self.getFiles()
    return renderers.TreeGrid([("Offset", format_hints.Hex), ("Rule", str), ("Component", str), ("Values", bytes)], self._generator())
      
  # Function brought from the actual yarascan module of volatitlity since there was no way to use it without it being within the module. 
  def _generator(self):
    i=0
    # Cycle that runs through all the files and executes the plugin yarascan, and writes the output into the different CSV files
    while i<len(self.files):
      self.config['yara_file'] = self.files[i]
      print(self.config['yara_file'])
      rules = yarascan.YaraScan.process_yara_options(dict(self.config))
      f = open('results_'+self.files[i].replace('/','_').replace(':','_').replace('\\','_')+'.csv','w')
      f.write(self.files[i]+'\n')
      i+=1
      f.write('Offset,Rule,Name,Value\n')
      layer = self.context.layers[self.config['primary']]
      for offset, rule_name, name, value in layer.scan(context = self.context, scanner = yarascan.YaraScanner(rules = rules)):

          f.write(format(hex((format_hints.Hex(offset))))+','+ str(rule_name)+','+str(name)+','+str(value)[1:]+'\n')



  # Function getFiles gets all the files from the folder and puts them all into an array to be used later by the Yara module
  def getFiles(self):
    if self.config.get('category',None):
      basepath='C:/yara/'+self.config['category']+'/'
      print(basepath)
      self.folder = os.listdir(basepath)
      for path, subdirs, files in os.walk(basepath):
        for name in files:
          if name.endswith(".yar"):
            file = "file:"+os.path.join(path,name)
            self.files.append(file)
    else:
      folder = self.custom_rules
      for path,subdirs, files in os.walk(folder):
        for name in files:
          if name.endswith(".yar"):
            rule = "file:"+os.path.join(path,name)
            self.files.append(rule)  

  # Function to verify if the repositories exist in the system and if not download them all into the system creating the respective folder
  def gitClone(self):
    if not os.path.exists(self.root_path+self.folders[0]):
      i = 0
      for link in self.repositoriesURL:
        print(link)
        path = os.path.join(self.root_path,self.folders[i])
        print('path: '+path)
        repo = pygit2.clone_repository(link,path)

        i += 1
        print(i)
      print("Repositories successfully cloned")

    else:
      print("Repositories already exist, use the pull option instead")
    quit()

  # Function that checks if the repositories exist in the system and if they do and have updates downloads all those updates for every repository
  def gitPull(self):
    if os.path.exists(self.root_path+self.folders[0]):
      paths = []
      for path in os.listdir(self.root_path):
        full_path = os.path.join(self.root_path,path)
        paths.append(full_path)
  
        for folder in paths:
          repo = pygit2.Repository(folder)
          self.pull(repo)
      print("Repositories successfully updated")
      
    else:
      print("Repositories need to be cloned before using the pull option")
    quit()

  # Function that uses the pull method of git and is ran for each repository that exists
  def pull(self,repo, remote_name='origin'):
    for remote in repo.remotes:
        if remote.name == remote_name:
            remote.fetch()
            remote_master_id = repo.lookup_reference('refs/remotes/origin/master').target
            merge_result, _ = repo.merge_analysis(remote_master_id)
            # Up to date, do nothing
            if merge_result & pygit2.GIT_MERGE_ANALYSIS_UP_TO_DATE:
                return
            # We can just fastforward
            elif merge_result & pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
                repo.checkout_tree(repo.get(remote_master_id))
                master_ref = repo.lookup_reference('refs/heads/master')
                master_ref.set_target(remote_master_id)
                repo.head.set_target(remote_master_id)
            elif merge_result & pygit2.GIT_MERGE_ANALYSIS_NORMAL:
                repo.merge(remote_master_id)
                print (repo.index.conflicts)

                assert repo.index.conflicts is None, 'Conflicts, ahhhh!'
                user = repo.default_signature
                tree = repo.index.write_tree()
                commit = repo.create_commit('HEAD',
                                            user,
                                            user,
                                            'Merge!',
                                            tree,
                                            [repo.head.target, remote_master_id])
                repo.state_cleanup()
            else:
                raise AssertionError('Unknown merge analysis result')