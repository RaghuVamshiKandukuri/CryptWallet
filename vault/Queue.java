import java.util.*;
public class Queue {
    int size;
    Queue(int size){
        this.size = size;
    }
    public int array[] = new int[size];
    public int rear = -1;
    public int  front = -1;


    public void insert(int data)
    {
        if (front == size) {
            System.out.println("Queue Overflow...");
            return;
        }
        if (rear==-1&&front==-1) {
            rear = rear + 1;
            front = front+1;
            array[front] = data;
            front = front+1;
            System.out.println(data+" Data inserted...");
        }
        else{
            array[front] = data;
            front = front+1;
            System.out.println(data+" Data inserted...");
        }
    }

    public void delete(){
        if (rear==-1) {
            System.out.println("Queue is empty underflow...");
            return;
        }
        System.out.println(array[rear]+" data deleted...");
        rear = rear + 1;
    }

    public void display(){
        int temp = rear;
        System.out.print("Queue -->");
        for(int i=0;i<size;i++){
            System.out.print(array[temp]);
            if (i<size-1) {
                System.out.print(" --> ");
            }
        }
    }
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        
        
    }
}