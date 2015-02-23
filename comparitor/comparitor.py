mapf = open('zygote.map')
commonf = open('commonlines.vm')

for line in mapf:
    range_str = line.split(' ')[0]
    range_ends = range_str.split('-')
    start = int(range_ends[0], 16)
    end = int(range_ends[1], 16)
    commonf.seek(0)
    for line2 in commonf:
        target = int(line2.split('\t')[1], 16)
        if (target >= start) and (target <= end):
            print line.strip('\n')
            break

commonf.close()
mapf.close()
