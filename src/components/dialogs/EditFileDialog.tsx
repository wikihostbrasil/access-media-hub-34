import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

interface EditFileDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  file?: any;
}

export const EditFileDialog = ({ open, onOpenChange }: EditFileDialogProps) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Editar arquivo</DialogTitle>
          <DialogDescription>Funcionalidade a ser implementada</DialogDescription>
        </DialogHeader>
        <Button onClick={() => onOpenChange(false)}>Fechar</Button>
      </DialogContent>
    </Dialog>
  );
};