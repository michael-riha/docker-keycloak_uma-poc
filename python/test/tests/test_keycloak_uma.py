# content of test_sample.py
def func(x):
    return x + 1

def test_it():
    print('here') # <- add breakpoint here

def test_answer():
    result= func(4)
    print(f"let's test the answer: {result}")
    assert result == 5