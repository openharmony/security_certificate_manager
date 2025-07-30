#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

def merge_files(input_dir, output_file):
    if not os.path.isdir(input_dir):
        print(f"Error: {input_dir} is not a valid directory", file=sys.stderr)
        sys.exit(1)

    with open(output_file, 'w') as out_f:
        for filename in sorted(os.listdir(input_dir)):
            filepath = os.path.join(input_dir, filename)
            if os.path.isfile(filepath):
                with open(filepath, 'r') as in_f:
                    out_f.write(in_f.read())
                out_f.write("\n\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_dir> <output_file>", file=sys.stderr)
        sys.exit(1)
    merge_files(sys.argv[1], sys.argv[2])
 