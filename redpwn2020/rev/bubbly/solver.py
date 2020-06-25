#!/usr/bin/python

def notSorted(arr):
    for n in range(len(arr)-1):
        if arr[n] > arr[n+1]:
            return True

    return False

nums = [1, 10, 3, 2, 5, 9, 8, 7, 4, 6]
sequence = ''

while notSorted(nums):
    for n in range(len(nums)-1):
        if nums[n] > nums[n+1]:
            sequence += str(n) + ' '
            temp = nums[n]
            nums[n] = nums[n+1]
            nums[n+1] = temp

print(sequence + '9')

